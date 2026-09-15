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
    # Mirrors the real call: -o /dev/null -w '%{http_code}' prints the status.
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

# --- the binding MDMA recomputes ------------------------------------------
# The contract. MDMA computes SHA256(challenge|peer|account|relay) from the
# request body and requires the quote to carry it, so the nonce the sidecar
# asked merod to attest over must match that exactly.
reconcile_registration "${PEER}" "${ACCOUNT}" "${RELAY}" 2428
[[ "$(registrations)" == "1" ]] || fail "expected one registration, got $(registrations)"

expected="$(python3 -c "
import hashlib
print(hashlib.sha256('|'.join(['chal-one', '${PEER}', '${ACCOUNT}', '${RELAY}']).encode()).hexdigest())
")"
sent="$(python3 -c "import json,sys; print(json.loads(sys.stdin.readline())['nonce'])" < "${SB}/attest-log")"
[[ "${sent}" == "${expected}" ]] \
  || fail "the attested nonce is not what mdma will recompute: ${sent} != ${expected}"
[[ "$(field 0 challenge)" == "chal-one" ]] || fail "the challenge must travel with the registration"
[[ "$(field 0 quote)" == "cXVvdGUtYnl0ZXM=" ]] || fail "the quote must be forwarded verbatim"

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

echo "PASS: fleet sidecar attested registration"
