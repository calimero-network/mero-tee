#!/usr/bin/env bash
# Behavioural test for the fleet sidecar's attested node registration.
#
# Everything the sidecar tells MDMA about itself was previously taken on trust:
# the fleet token says "some node", never "which node", so MDMA could not tell
# one node's claims from another's — and `should_join` compared a REPORTED mrtd
# against a customer's measurement allowlist (calimero-network/mdma#225).
#
# Registration binds those claims to a quote, and the binding is a hash the two
# sides compute independently. That makes it exactly the kind of contract that
# breaks silently: get the field order or the separator wrong and MDMA rejects
# every quote as bound to a different identity, which looks identical to a node
# whose attestation is genuinely bad.
#
# Three more things that fail quietly:
#   * recording a registration MDMA did not accept — the node then never
#     retries, and is never advertised, for as long as it runs;
#   * treating MDMA's 503 ("could not EVALUATE the quote") as a refusal — an
#     Intel collateral outage would permanently unregister a healthy fleet;
#   * re-registering every cycle — a quote per second, and a spent challenge
#     each time, for an identity that never changes.
#
# Usage: scripts/ci/tests/fleet-sidecar-registration-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
export SB
mkdir -p "${SB}/bin"

sed -e 's@{{ fleet_mdma_url }}@https://mdma.test@' \
    -e "s@{{ fleet_auth_token | default('') }}@@" \
    -e "s@/var/log/fleet-sidecar.log@${SB}/fleet.log@" \
    -e "s@/var/lib/calimero/@${SB}/@g" \
    -e "s@/mnt/data/tls@${SB}/tls@g" \
    -e "s@/var/lib/calimero/@${SB}/@g" \
    "${TEMPLATE}" > "${SB}/rendered.sh"
sed -n '1,/^# --- Main loop ---$/p' "${SB}/rendered.sh" | sed '$d' > "${SB}/functions.sh"

if grep -q '{{\|{%' "${SB}/functions.sh"; then
  echo "FAIL: unsubstituted Jinja left in the rendered sidecar" >&2
  exit 1
fi

# `curl` stands in for both hops: GCP metadata, MDMA, and merod's attest route.
#   ${SB}/challenge      the challenge MDMA hands out
#   ${SB}/register-code  the HTTP status MDMA answers /nodes/register with
#   ${SB}/attest-fails   while present, merod's attest route errors
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
  *metadata.google.internal*server-port*) echo "2428"; exit 0 ;;
  *metadata.google.internal*relay-url*)   echo "https://relay-01.test"; exit 0 ;;
  *metadata.google.internal*)             exit 1 ;;
  *nodes/challenge*)
    printf '{"challenge":"%s","expires_at_ms":1}\n' "$(cat "${SB}/challenge")"
    exit 0 ;;
  *admin-api/tee/attest*)
    [[ -f "${SB}/attest-fails" ]] && exit 22
    printf '%s\n' "${body}" >> "${SB}/attest-log"
    echo '{"data":{"quoteB64":"cXVvdGUtYnl0ZXM="}}'
    exit 0 ;;
  *nodes/register*)
    printf '%s\n' "${body}" >> "${SB}/register-log"
    code="$(cat "${SB}/register-code" 2>/dev/null || echo 200)"
    # The real call writes the body with `-o <file>` and prints the status with
    # `-w '%{http_code}'`. The body matters now: registration is where mdma
    # ISSUES the fleet token, so a stub that returned none would leave the node
    # tokenless and re-registering on its retry clock forever.
    out=""
    prev=""
    for a in "$@"; do
      [[ "${prev}" == "-o" ]] && out="${a}"
      prev="${a}"
    done
    [[ -n "${out}" ]] && printf '{"status":"registered","fleet_token":"f1.%s.deadbeef"}' \
      "12D3KooWSidecarRegistrationPeer" > "${out}"
    for a in "$@"; do [[ "${a}" == "%{http_code}" ]] && { echo "${code}"; exit 0; }; done
    exit 0 ;;
esac
exit 1
STUB
chmod +x "${SB}/bin/curl"
PATH="${SB}/bin:${PATH}"
export PATH

# shellcheck source=/dev/null
source "${SB}/functions.sh"

: > "${SB}/attest-log"
: > "${SB}/register-log"
echo "chal-one" > "${SB}/challenge"
echo "200" > "${SB}/register-code"

PEER="12D3KooWSidecarRegistrationPeer"
ACCOUNT="4d4d4d"
RELAY="https://relay-01.test"

fail() { echo "FAIL: $*" >&2; exit 1; }
registrations() { awk 'NF{n++} END{print n+0}' "${SB}/register-log"; }
field() { python3 -c "
import json,sys
print(json.loads(sys.stdin.read().strip().split(chr(10))[int(sys.argv[1])])[sys.argv[2]])
" "$1" "$2" < "${SB}/register-log"; }

# The node key calimero-init generates before traefik starts. Present here
# because its CSR is part of what the quote commits to.
mkdir -p "${SB}/tls"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "${SB}/tls/key.pem" -out "${SB}/tls/cert.pem" -days 3650 \
  -subj "/CN=calimero-fleet-node" 2>/dev/null

# --- the binding MDMA recomputes ------------------------------------------
# The contract. MDMA computes SHA256(challenge|peer|account|relay|sha256(csr))
# from the request body and requires the quote to carry it, so the nonce the
# sidecar asked merod to attest over must match that exactly.
#
# The CSR digest is in there because a quote that commits only to the identity
# proves WHICH NODE is asking and says nothing about the key travelling beside
# it -- mdma would then sign a certificate for whatever key reached it. With the
# digest bound, the certificate provably belongs to a key born in this enclave.
reconcile_registration "${PEER}" "${ACCOUNT}" "${RELAY}" 2428
[[ "$(registrations)" == "1" ]] || fail "expected one registration, got $(registrations)"

csr="$(field 0 csr)"
[[ -n "${csr}" ]] || fail "the CSR must travel with the registration"
echo "${csr}" | base64 -d | openssl req -inform DER -noout -text \
  | grep -q "DNS:relay-01.test" || fail "the CSR must be for the relay hostname"

expected="$(python3 -c "
import hashlib, sys
csr_digest = hashlib.sha256(sys.argv[1].encode()).hexdigest()
print(hashlib.sha256('|'.join(['chal-one', '${PEER}', '${ACCOUNT}', '${RELAY}', csr_digest]).encode()).hexdigest())
" "${csr}")"
sent="$(python3 -c "import json,sys; print(json.loads(sys.stdin.readline())['nonce'])" < "${SB}/attest-log")"
[[ "${sent}" == "${expected}" ]] \
  || fail "the attested nonce is not what mdma will recompute: ${sent} != ${expected}"
[[ "$(field 0 challenge)" == "chal-one" ]] || fail "the challenge must travel with the registration"
[[ "$(field 0 quote)" == "cXVvdGUtYnl0ZXM=" ]] || fail "the quote must be forwarded verbatim"

# --- no CSR falls back to the four-field binding --------------------------
# What a node image from before this change sends, and what a node with no
# relay URL sends today. mdma accepts both shapes; a node that only replicates
# must keep registering, or rolling out relay TLS would unregister the fleet.
rm -f "${SB}/fleet-registration.json" "${SB}/tls/key.pem"
rm -f "${SB}"/tls/csr-*.b64
: > "${SB}/attest-log"
: > "${SB}/register-log"
echo "chal-nokey" > "${SB}/challenge"
reconcile_registration "${PEER}" "${ACCOUNT}" "${RELAY}" 2428
[[ "$(registrations)" == "1" ]] || fail "a node with no TLS key must still register"
[[ -z "$(python3 -c "
import json,sys
print(json.loads(sys.stdin.readline()).get('csr',''))
" < "${SB}/register-log")" ]] || fail "no key means no csr field at all"
expected="$(python3 -c "
import hashlib
print(hashlib.sha256('|'.join(['chal-nokey', '${PEER}', '${ACCOUNT}', '${RELAY}']).encode()).hexdigest())
")"
sent="$(python3 -c "import json,sys; print(json.loads(sys.stdin.readline())['nonce'])" < "${SB}/attest-log")"
[[ "${sent}" == "${expected}" ]] \
  || fail "without a CSR the binding must stay four fields: ${sent} != ${expected}"

# Restore the key and the starting state for the cases below.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "${SB}/tls/key.pem" -out "${SB}/tls/cert.pem" -days 3650 \
  -subj "/CN=calimero-fleet-node" 2>/dev/null
rm -f "${SB}/fleet-registration.json"
: > "${SB}/attest-log"
: > "${SB}/register-log"
echo "chal-one" > "${SB}/challenge"
reconcile_registration "${PEER}" "${ACCOUNT}" "${RELAY}" 2428

# --- an unchanged identity does not re-register ---------------------------
reconcile_registration "${PEER}" "${ACCOUNT}" "${RELAY}" 2428
reconcile_registration "${PEER}" "${ACCOUNT}" "${RELAY}" 2428
[[ "$(registrations)" == "1" ]] || fail "a stable identity must not re-register every cycle"

# --- a changed identity re-registers --------------------------------------
echo "chal-two" > "${SB}/challenge"
reconcile_registration "${PEER}" "${ACCOUNT}" "https://relay-02.test" 2428
[[ "$(registrations)" == "2" ]] || fail "a changed relay url must re-register"
[[ "$(field 1 relay_url)" == "https://relay-02.test" ]] || fail "the new identity must be sent"

# --- 503 is retried, not recorded -----------------------------------------
# "Could not EVALUATE the quote" is not "your quote is bad". Recording it would
# leave a healthy node unregistered for as long as it runs.
rm -f "${SB}/fleet-registration.json"
: > "${SB}/register-log"
echo "503" > "${SB}/register-code"
reconcile_registration "${PEER}" "${ACCOUNT}" "${RELAY}" 2428
echo "200" > "${SB}/register-code"
reconcile_registration "${PEER}" "${ACCOUNT}" "${RELAY}" 2428
[[ "$(registrations)" == "2" ]] || fail "a 503 must be retried on the next pass"

# --- a refusal is likewise not recorded -----------------------------------
rm -f "${SB}/fleet-registration.json"
: > "${SB}/register-log"
echo "403" > "${SB}/register-code"
reconcile_registration "${PEER}" "${ACCOUNT}" "${RELAY}" 2428
echo "200" > "${SB}/register-code"
reconcile_registration "${PEER}" "${ACCOUNT}" "${RELAY}" 2428
[[ "$(registrations)" == "2" ]] || fail "a 403 must not be recorded as a completed registration"

# --- merod unreachable writes nothing -------------------------------------
rm -f "${SB}/fleet-registration.json"
: > "${SB}/register-log"
touch "${SB}/attest-fails"
reconcile_registration "${PEER}" "${ACCOUNT}" "${RELAY}" 2428
rm -f "${SB}/attest-fails"
[[ "$(registrations)" == "0" ]] || fail "no quote means no registration attempt"

# --- a half identity is not registered ------------------------------------
# A node with no account cannot be advertised as a relay anyway, so binding a
# half-identity would only record something that has to be replaced.
rm -f "${SB}/fleet-registration.json"
: > "${SB}/register-log"
reconcile_registration "${PEER}" "" "${RELAY}" 2428
[[ "$(registrations)" == "0" ]] || fail "an identity with no account must not register"

# --- the token is EARNED, never baked --------------------------------------
# The image carries no fleet credential. mdma issues one scoped to this peer
# when the quote verifies, and the sidecar stores it 0600. A node that has none
# must register whatever its recorded identity says -- that is the only way to
# get one -- but on a clock, because each attempt costs a quote and spends a
# single-use challenge, and a 1 Hz retry against a manager that will not issue
# one is a quote per second forever.
[[ -s "${SB}/fleet-token" ]] || fail "registration must store the issued fleet token"
grep -q "^f1\." "${SB}/fleet-token" || fail "the stored token must be the one mdma issued"
perms=$(stat -c %a "${SB}/fleet-token")
[[ "${perms}" == "600" ]] || fail "the fleet token must be 0600, got ${perms}"

grep -q "fleet_auth_token\|FLEET_AUTH_TOKEN" "${SB}/rendered.sh" \
  && fail "no fleet credential may be baked into the rendered sidecar"

# shellcheck disable=SC2034  # both are read by reconcile_registration, sourced above
FLEET_TOKEN=""
rm -f "${SB}/fleet-token"
# shellcheck disable=SC2034  # ditto
LAST_REGISTRATION_ATTEMPT=$(date +%s)
before="$(registrations)"
reconcile_registration "${PEER}" "${ACCOUNT}" "${RELAY}" 2428
[[ "$(registrations)" == "${before}" ]] \
  || fail "a tokenless node must not re-register faster than REGISTRATION_RETRY_INTERVAL"

# shellcheck disable=SC2034  # ditto
LAST_REGISTRATION_ATTEMPT=0
reconcile_registration "${PEER}" "${ACCOUNT}" "${RELAY}" 2428
[[ "$(registrations)" -gt "${before}" ]] \
  || fail "a tokenless node must register once the retry interval has passed"

echo "PASS: fleet sidecar attested registration"
