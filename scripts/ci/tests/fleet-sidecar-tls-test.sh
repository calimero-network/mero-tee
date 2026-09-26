#!/usr/bin/env bash
# Behavioural test for the fleet sidecar's TLS certificate handling.
#
# A fleet node cannot be reached by a browser at all without this: a page served
# over HTTPS may not call an `http://` origin, and mixed content is blocked with
# no override. So the node terminates TLS itself, with a key it generated in the
# enclave and a certificate mdma orders for it over ACME DNS-01.
#
# Four ways that fails silently, which is why they are asserted here:
#
#   * the self-signed placeholder calimero-init writes reporting its own expiry.
#     It is valid for ten years, so mdma would conclude the node is covered
#     until 2036 and never order anything -- the node serves an untrusted
#     certificate forever and nobody is told.
#   * installing a certificate that does not match the node's key. traefik loads
#     it happily; every client handshake then fails, on a node mdma has already
#     advertised as a relay.
#   * a `log` line landing on stdout of a function whose stdout IS its value.
#     `log` tees, so `csr=$(node_csr_b64 ...)` captures the warning text and
#     mdma is asked to sign "WARN: no TLS key at ...".
#   * restarting traefik on every poll. The certificate arrives on a poll that
#     runs once a second, so an unchanged chain must be a no-op.
#
# Usage: scripts/ci/tests/fleet-sidecar-tls-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
export SB
mkdir -p "${SB}/bin" "${SB}/tls"

sed -e 's@{{ fleet_mdma_url }}@https://mdma.test@' \
    -e "s@{{ fleet_auth_token | default('') }}@@" \
    -e "s@/run/calimero/fleet-sidecar.log@${SB}/fleet.log@" \
    -e "s@/mnt/data/fleet/@${SB}/@g" \
    -e "s@/mnt/data/tls@${SB}/tls@g" \
    "${TEMPLATE}" > "${SB}/rendered.sh"
sed -n '1,/^# --- Main loop ---$/p' "${SB}/rendered.sh" | sed '$d' > "${SB}/functions.sh"

if grep -q '{{\|{%' "${SB}/functions.sh"; then
  echo "FAIL: unsubstituted Jinja left in the rendered sidecar" >&2
  exit 1
fi

# `systemctl` records restarts instead of performing them.
cat > "${SB}/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "${SB}/systemctl.calls"
STUB

# `curl` answers the poll with whatever ${SB}/poll-response holds.
cat > "${SB}/bin/curl" <<'STUB'
#!/usr/bin/env bash
url=""
body=""
prev=""
for a in "$@"; do
  [[ "${prev}" == "-d" ]] && body="${a}"
  [[ "${a}" == http* ]] && url="${a}"
  prev="${a}"
done
case "${url}" in
  *should-join*)
    printf '%s\n' "${body}" >> "${SB}/poll-log"
    cat "${SB}/poll-response"
    exit 0 ;;
esac
exit 1
STUB
chmod +x "${SB}/bin/systemctl" "${SB}/bin/curl"
PATH="${SB}/bin:${PATH}"
export PATH

# shellcheck source=/dev/null
source "${SB}/functions.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
: > "${SB}/systemctl.calls"
: > "${SB}/poll-log"

HOST="relay-07.relay.calimero.test"

# --- the hostname comes from the relay URL, not from anywhere on the node ----
# merod terminates no TLS and was never told its own address, so the URL mdma
# put in instance metadata is the only statement of what this node is called.
[[ "$(relay_host "https://${HOST}")" == "${HOST}" ]] || fail "relay_host bare"
[[ "$(relay_host "https://${HOST}/admin-api/x")" == "${HOST}" ]] || fail "relay_host with a path"
[[ -z "$(relay_host '')" ]] || fail "no relay url must yield no host"
[[ -z "$(relay_host 'not a url')" ]] || fail "garbage must yield no host"

# --- what calimero-init leaves behind before traefik starts -----------------
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "${SB}/tls/key.pem" -out "${SB}/tls/cert.pem" -days 3650 \
  -subj "/CN=calimero-fleet-node" 2>/dev/null

# The placeholder must report NO expiry. Reporting its real one (ten years out)
# would tell mdma this node is covered and no certificate would ever be ordered.
[[ -z "$(installed_cert_not_after)" ]] \
  || fail "the self-signed placeholder reported an expiry: $(installed_cert_not_after)"

# --- the CSR ----------------------------------------------------------------
CSR="$(node_csr_b64 "${HOST}")" || fail "could not build a CSR"
echo "${CSR}" | base64 -d | openssl req -inform DER -noout -text \
  | grep -q "DNS:${HOST}" || fail "the CSR must carry the hostname as a SAN"
[[ "$(node_csr_b64 "${HOST}")" == "${CSR}" ]] \
  || fail "the CSR must be stable: the registration nonce commits to its digest"

# A node that moves behind a different name asks for the new one, and the old
# CSR does not linger to be sent for a name this node no longer answers to.
OTHER="$(node_csr_b64 "relay-09.relay.calimero.test")" || fail "CSR for a second host"
[[ "${OTHER}" != "${CSR}" ]] || fail "the CSR must change with the hostname"
[[ ! -f "${SB}/tls/csr-${HOST}.b64" ]] || fail "the superseded CSR must be removed"

# With no key there is no CSR -- and, crucially, no log line masquerading as one.
mv "${SB}/tls/key.pem" "${SB}/tls/key.pem.bak"
NOKEY="$(node_csr_b64 "${HOST}" || true)"
[[ -z "${NOKEY}" ]] || fail "a missing key must yield an empty CSR, got: ${NOKEY}"
mv "${SB}/tls/key.pem.bak" "${SB}/tls/key.pem"

# --- installing what mdma returns -------------------------------------------
# A CA that is not us, standing in for Let's Encrypt.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "${SB}/ca.key" -out "${SB}/ca.crt" -days 30 -subj "/CN=test-ca" 2>/dev/null

# A certificate for somebody else's key must be refused, and must not disturb
# what is already installed.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "${SB}/impostor.key" -out "${SB}/impostor.crt" -days 30 \
  -subj "/CN=${HOST}" 2>/dev/null
before="$(sha256sum "${SB}/tls/cert.pem" | cut -d' ' -f1)"
install_certificate "$(cat "${SB}/impostor.crt")" >/dev/null \
  && fail "installed a certificate that does not match this node's key"
[[ "$(sha256sum "${SB}/tls/cert.pem" | cut -d' ' -f1)" == "${before}" ]] \
  || fail "a refused certificate overwrote the installed one"
[[ ! -s "${SB}/systemctl.calls" ]] || fail "a refused certificate must not restart traefik"

# The real thing: signed over the CSR this node produced.
openssl x509 -req -inform DER -in <(node_csr_b64 "${HOST}" | base64 -d) \
  -CA "${SB}/ca.crt" -CAkey "${SB}/ca.key" -CAcreateserial -days 90 \
  -out "${SB}/issued.pem" 2>/dev/null
install_certificate "$(cat "${SB}/issued.pem")" >/dev/null \
  || fail "refused a certificate that matches this node's key"
grep -q "restart traefik" "${SB}/systemctl.calls" \
  || fail "traefik must be restarted: it watches its config file, not the certificate"

# Now that a real certificate is installed, the expiry is reported -- which is
# what stops mdma re-ordering one every second, and what drives renewal later.
NOT_AFTER="$(installed_cert_not_after)"
[[ "${NOT_AFTER}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]] \
  || fail "expiry must be RFC3339, got: ${NOT_AFTER}"

# --- delivery rides the poll ------------------------------------------------
# No new endpoint and no blocking call: issuance is asynchronous on mdma's side,
# so the chain appears on whichever poll follows it.
rm -f "${SB}/tls/cert.pem"
openssl req -x509 -new -nodes -key "${SB}/tls/key.pem" -out "${SB}/tls/cert.pem" \
  -days 3650 -subj "/CN=calimero-fleet-node" 2>/dev/null
: > "${SB}/systemctl.calls"
# Read by `poll_mdma` out of the sourced sidecar, not by this script.
# shellcheck disable=SC2034
RELAY_URL="https://${HOST}"
# shellcheck disable=SC2034
EXECUTOR_ACCOUNT="4d4d4d"
python3 - "${SB}/issued.pem" > "${SB}/poll-response" <<'PY'
import json, sys
print(json.dumps({"assignments": [], "tls_certificate": open(sys.argv[1]).read()}))
PY

out="$(poll_mdma "12D3KooWTlsPeer" "aa" )" || fail "poll failed"
python3 -c "
import json, sys
data = json.loads(sys.argv[1])
if not isinstance(data.get('assignments'), list):
    raise SystemExit('poll returned something that is not an assignments payload')
" "${out}" || fail "the install must not contaminate the poll's stdout: ${out}"
grep -q "restart traefik" "${SB}/systemctl.calls" || fail "the polled certificate was not installed"

# That poll asked for a certificate: it was built while the placeholder was
# still installed, so it reported no expiry. That empty value IS the request.
reported() { python3 -c "
import json,sys
print(json.loads(sys.stdin.read().strip().split(chr(10))[-1]).get('tls_cert_not_after',''))
" < "${SB}/poll-log"; }
[[ -z "$(reported)" ]] \
  || fail "a node holding only the placeholder must report no expiry, got: $(reported)"

# --- an unchanged certificate is a no-op ------------------------------------
# The poll runs every second; re-installing identical bytes would restart
# traefik every second with it.
: > "${SB}/systemctl.calls"
poll_mdma "12D3KooWTlsPeer" "aa" >/dev/null || fail "second poll failed"
[[ ! -s "${SB}/systemctl.calls" ]] \
  || fail "an unchanged certificate must not restart traefik"

# And now that the chain is installed, the next poll carries its expiry, which
# is what stops mdma re-ordering every second and what drives renewal later.
[[ -n "$(reported)" ]] \
  || fail "once installed, the poll must report the certificate's expiry"
[[ "$(reported)" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T ]] \
  || fail "the reported expiry must be RFC3339, got: $(reported)"

echo "PASS: fleet sidecar TLS certificate handling"
