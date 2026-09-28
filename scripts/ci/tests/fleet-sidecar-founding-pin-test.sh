#!/usr/bin/env bash
# Behavioural test for the fleet sidecar's legacy namespace founding: the pin
# it posts for mdma, and the legacy form of the admin verification.
#
# A namespace founded before derived ids (a V1 genesis) has no `founding`, so
# `founder_matches` could never be true for it. merod reports such a replica's
# founder and genesis op as `legacyFounding: {founderAccountId, genesisOpHash}`
# on `namespace get`. mdma asks one node to pin it -- a `should-join`
# assignment carrying `pin_founding: true` -- and the node, once confirmed,
# posts
#   POST /api/fleet/namespaces/<ns>/founding
#   {"peer_id", "founder_account_id", "genesis_op_hash"}
# Later verifications of that namespace carry `verify.genesis_op_hash`, and are
# answered from `legacyFounding` ALONE, both fields matching.
#
# Every way this is wrong is quiet:
#   * a pin posted without being asked, or from a namespace with no
#     `legacyFounding`, pins a founder mdma did not ask about;
#   * a pin posted every cycle writes to mdma once a second; one recorded before
#     mdma acknowledged it is never delivered;
#   * a legacy question answered from the founder alone would accept any
#     namespace that founder ever made, and one answered from `founding` would
#     let a derived namespace answer a legacy question;
#   * `legacyFounding` satisfying a DERIVED question would let a legacy replica
#     pass the check derived ids exist to make.
#
# Same harness as fleet-sidecar-verification-test.sh: render the template,
# source the function half, drive it against stubbed `meroctl` and `curl`.
#
# Usage: scripts/ci/tests/fleet-sidecar-founding-pin-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
export SB

fail() { echo "FAIL: $*" >&2; exit 1; }

[[ -r "${TEMPLATE}" ]] || fail "cannot read ${TEMPLATE}"

# --- render the template ---------------------------------------------------
sed -e 's@{{ fleet_mdma_url }}@https://mdma.test@' \
    -e "s@{{ fleet_auth_token | default('') }}@@" \
    -e "s@/run/calimero/fleet-sidecar.log@${SB}/fleet.log@" \
    -e "s@/mnt/data/fleet/@${SB}/@g" \
    -e "s@/etc/vector@${SB}/vector@g" \
    -e "s@/etc/vmagent@${SB}/vmagent@g" \
    "${TEMPLATE}" > "${SB}/rendered.sh"

grep -q '^# --- Main loop ---$' "${SB}/rendered.sh" \
  || fail "no '# --- Main loop ---' marker; this test slices on it"
sed -n '1,/^# --- Main loop ---$/p' "${SB}/rendered.sh" | sed '$d' > "${SB}/functions.sh"

if grep -q '{{\|{%' "${SB}/functions.sh"; then
  grep -n '{{\|{%' "${SB}/functions.sh" >&2
  fail "unsubstituted Jinja left in the rendered sidecar"
fi
if leaked="$(grep -nE '^[A-Za-z_]+_FILE="[^"]*"' "${SB}/functions.sh" | grep -v "${SB}/")"; then
  echo "${leaked}" >&2
  fail "the rendered sidecar keeps state outside the sandbox"
fi

# The loop must call it, after the verification and never fatally: a failure
# here must not break join, leave or inventory.
loop="$(sed -n '/^# --- Main loop ---$/,$p' "${SB}/rendered.sh")"
# shellcheck disable=SC2016
grep -q 'reconcile_founding_pin "\$PEER_ID" "\$response" "\$confirmed" || true' <<< "${loop}" \
  || fail "the main loop does not call reconcile_founding_pin over the confirmed set, guarded by || true"
# shellcheck disable=SC2016
verify_line="$(grep -n 'reconcile_verification "\$PEER_ID"' <<< "${loop}" | head -1 | cut -d: -f1)"
# shellcheck disable=SC2016
pin_line="$(grep -n 'reconcile_founding_pin "\$PEER_ID"' <<< "${loop}" | head -1 | cut -d: -f1)"
(( pin_line > verify_line )) || fail "reconcile_founding_pin must run after reconcile_verification"

# --- stubs -----------------------------------------------------------------
mkdir -p "${SB}/bin" "${SB}/ns" "${SB}/members"

cat > "${SB}/bin/meroctl" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SB}/meroctl-log"
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  if [[ "${args[i]}" == "namespace" && "${args[i + 1]:-}" == "get" ]]; then
    f="${SB}/ns/${args[i + 2]}"
    [[ -f "${f}" ]] || { echo "Namespace not found" >&2; exit 1; }
    cat "${f}"
    exit 0
  fi
  if [[ "${args[i]}" == "members" && "${args[i + 1]:-}" == "list" ]]; then
    f="${SB}/members/${args[i + 2]}"
    [[ -f "${f}" ]] || { echo "Group not found" >&2; exit 1; }
    cat "${f}"
    exit 0
  fi
done
exit 1
STUB

# `curl`: records "<url> <token header> <body>" per POST to ${SB}/post-log and
# answers ${SB}/reply (default `{"status":"pinned"}`), or fails while
# ${SB}/post-fails exists.
cat > "${SB}/bin/curl" <<'STUB'
#!/usr/bin/env bash
body="" url="" token="" prev=""
for a in "$@"; do
  [[ "${prev}" == "-d" ]] && body="${a}"
  [[ "${prev}" == "-H" && "${a}" == X-Fleet-Token:* ]] && token="${a}"
  [[ "${a}" == http* ]] && url="${a}"
  prev="${a}"
done
[[ -f "${SB}/post-fails" ]] && exit 22
printf '%s\t%s\t%s\n' "${url}" "${token}" "${body}" >> "${SB}/post-log"
cat "${SB}/reply" 2>/dev/null || echo '{"status":"pinned"}'
STUB
chmod +x "${SB}/bin/meroctl" "${SB}/bin/curl"
PATH="${SB}/bin:${PATH}"
export PATH

# shellcheck source=/dev/null
source "${SB}/functions.sh"
# Read by the sourced sidecar functions, which shellcheck cannot follow.
# shellcheck disable=SC2034
MEROCTL="meroctl"
# shellcheck disable=SC2034
FLEET_TOKEN="f1.peer1.sig"
: > "${SB}/post-log"
: > "${SB}/meroctl-log"

hex() { printf "${1}%.0s" {1..64}; }
NS1="$(hex a)"; NS2="$(hex b)"; NS3="$(hex c)"; NS4="$(hex d)"
FOUNDER="$(hex 1)"; ADMIN="$(hex 2)"; OTHER="$(hex 3)"
GENESIS="$(hex 5)"; GENESIS2="$(hex 6)"

posts() { awk 'NF{n++} END{print n+0}' "${SB}/post-log"; }
expect_posts() {
  local want="$1" why="$2" got
  got="$(posts)"
  [[ "${got}" == "${want}" ]] || fail "${why} (expected ${want} posts, got ${got}): $(cat "${SB}/post-log")"
}
last_url() { tail -1 "${SB}/post-log" | cut -f1; }
last_body() { tail -1 "${SB}/post-log" | cut -f3; }
field() { python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])[sys.argv[2]]))' "$(last_body)" "$1"; }

# A should-join response. Each arg is "<ns>", "<ns>:pin" (pin_founding: true),
# "<ns>:<founder>:<account>" or "<ns>:<founder>:<account>:<genesis hash>".
response() {
  python3 -c '
import json, sys
out = []
for arg in sys.argv[1:]:
    parts = arg.split(":")
    entry = {"group_id": parts[0], "admitter_addrs": []}
    if parts[1:] == ["pin"]:
        entry["pin_founding"] = True
    elif len(parts) >= 3:
        entry["verify"] = {"founder_account_id": parts[1], "account_id": parts[2]}
        if len(parts) == 4:
            entry["verify"]["genesis_op_hash"] = parts[3]
    out.append(entry)
print(json.dumps({"assignments": out}))' "$@"
}
confirmed() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "$@"; }

# namespace fixture: namespace <ns> <derived founder or ""> [<legacy founder> <genesis hash>]
# Hex is written uppercase to prove it is compared case-insensitively.
namespace() {
  python3 -c '
import json, sys
data = {"namespaceId": sys.argv[1], "memberCount": 2}
if sys.argv[2]:
    data["founding"] = {"founderAccountId": sys.argv[2].upper(), "salt": "00" * 32}
if len(sys.argv) > 4:
    data["legacyFounding"] = {"founderAccountId": sys.argv[3].upper(), "genesisOpHash": sys.argv[4].upper()}
print(json.dumps({"data": data}))' "$@" > "${SB}/ns/$1"
}
members() {
  local ns="$1"; shift
  python3 -c '
import json, sys
print(json.dumps({"members": [{"identity": a, "role": r} for a, r in (arg.split("=") for arg in sys.argv[1:])]}))' \
    "$@" > "${SB}/members/${ns}"
}

# ============================ founding pin =================================

# 1. Asked, confirmed, legacyFounding present: one post to the founding route,
#    with the fleet token, carrying exactly the pin, lowercased.
namespace "${NS1}" "" "${FOUNDER}" "${GENESIS}"
reconcile_founding_pin peer1 "$(response "${NS1}:pin")" "$(confirmed "${NS1}")"
expect_posts 1 "a confirmed namespace asking for a pin must be pinned"
[[ "$(last_url)" == "https://mdma.test/api/fleet/namespaces/${NS1}/founding" ]] \
  || fail "posted to the wrong route: $(last_url)"
[[ "$(tail -1 "${SB}/post-log" | cut -f2)" == "X-Fleet-Token: f1.peer1.sig" ]] \
  || fail "the founding POST must carry the fleet token"
[[ "$(field peer_id)" == '"peer1"' ]] || fail "peer_id: $(last_body)"
[[ "$(field founder_account_id)" == "\"${FOUNDER}\"" ]] || fail "founder_account_id: $(last_body)"
[[ "$(field genesis_op_hash)" == "\"${GENESIS}\"" ]] || fail "genesis_op_hash: $(last_body)"
keys="$(python3 -c 'import json,sys; print(",".join(sorted(json.loads(sys.argv[1]))))' "$(last_body)")"
[[ "${keys}" == "founder_account_id,genesis_op_hash,peer_id" ]] \
  || fail "the founding body must carry exactly the pin fields, got: ${keys}"
grep -q "${NS1}" "${SB}/fleet-founding-pins.json" || fail "a delivered pin must be recorded"

# 2. Dedupe: the same pin is not posted again while mdma keeps asking.
reconcile_founding_pin peer1 "$(response "${NS1}:pin")" "$(confirmed "${NS1}")"
reconcile_founding_pin peer1 "$(response "${NS1}:pin")" "$(confirmed "${NS1}")"
expect_posts 1 "an acknowledged pin must not be re-posted"
# ...whatever mdma answered: `conflicted` is final too, and logged.
echo '{"status":"conflicted"}' > "${SB}/reply"
namespace "${NS4}" "" "${OTHER}" "${GENESIS}"
reconcile_founding_pin peer1 "$(response "${NS4}:pin")" "$(confirmed "${NS4}")"
reconcile_founding_pin peer1 "$(response "${NS4}:pin")" "$(confirmed "${NS4}")"
expect_posts 2 "a conflicted pin is an answer and must not be re-posted"
grep -q "WARN: mdma reports the legacy founding pin for namespace ${NS4}" "${SB}/fleet.log" \
  || fail "a conflicted pin must be logged as a warning"
rm -f "${SB}/reply"
# A DIFFERENT pair for the same namespace is a new answer.
namespace "${NS4}" "" "${OTHER}" "${GENESIS2}"
reconcile_founding_pin peer1 "$(response "${NS4}:pin")" "$(confirmed "${NS4}")"
expect_posts 3 "a changed genesis hash must be posted again"
[[ "$(field genesis_op_hash)" == "\"${GENESIS2}\"" ]] || fail "the new hash: $(last_body)"

# 3. Not asked: no pin_founding, no post, merod not even read. Also not when
#    pin_founding is anything but a literal true, or the namespace is not
#    confirmed yet.
: > "${SB}/meroctl-log"
reconcile_founding_pin peer1 "$(response "${NS2}")" "$(confirmed "${NS2}")"
namespace "${NS2}" "" "${FOUNDER}" "${GENESIS}"
reconcile_founding_pin peer1 '{"assignments":[{"group_id":"'"${NS2}"'","pin_founding":"true"},{"group_id":"'"${NS2}"'","pin_founding":1}]}' "$(confirmed "${NS2}")"
reconcile_founding_pin peer1 "$(response "${NS2}:pin")" "$(confirmed)"
expect_posts 3 "no pin may be posted unless asked, with a literal true, for a confirmed namespace"
[[ ! -s "${SB}/meroctl-log" ]] || fail "an unasked pin must not touch merod: $(cat "${SB}/meroctl-log")"

# 4. legacyFounding absent (a derived namespace, or a merod that predates the
#    field), malformed, or the namespace unreadable: nothing posted, nothing
#    recorded, one warning rather than one a second.
namespace "${NS3}" "${FOUNDER}"
warned_before="$(grep -c 'cannot pin the founding' "${SB}/fleet.log" || true)"
reconcile_founding_pin peer1 "$(response "${NS3}:pin")" "$(confirmed "${NS3}")"
reconcile_founding_pin peer1 "$(response "${NS3}:pin")" "$(confirmed "${NS3}")"
expect_posts 3 "no legacyFounding must post nothing"
warned_after="$(grep -c 'cannot pin the founding' "${SB}/fleet.log" || true)"
(( warned_after - warned_before == 1 )) \
  || fail "a persistently absent legacyFounding must warn once, got $(( warned_after - warned_before ))"
echo '{"data":{"legacyFounding":{"founderAccountId":"'"${FOUNDER}"'","genesisOpHash":"short"}}}' > "${SB}/ns/${NS3}"
reconcile_founding_pin peer1 "$(response "${NS3}:pin")" "$(confirmed "${NS3}")"
rm -f "${SB}/ns/${NS3}"
reconcile_founding_pin peer1 "$(response "${NS3}:pin")" "$(confirmed "${NS3}")"
expect_posts 3 "a malformed or unreadable legacyFounding must post nothing"
grep -q "${NS3}" "${SB}/fleet-founding-pins.json" && fail "an unpinned namespace must not be recorded"

# 5. A failed POST is not recorded, and is retried next cycle.
namespace "${NS3}" "" "${FOUNDER}" "${GENESIS}"
touch "${SB}/post-fails"
reconcile_founding_pin peer1 "$(response "${NS3}:pin")" "$(confirmed "${NS3}")"
reconcile_founding_pin peer1 "$(response "${NS3}:pin")" "$(confirmed "${NS3}")"
rm -f "${SB}/post-fails"
grep -q "${NS3}" "${SB}/fleet-founding-pins.json" && fail "a failed POST must not be recorded"
(( $(grep -c "founding failed" "${SB}/fleet.log") == 1 )) || fail "a failing POST must warn once"
reconcile_founding_pin peer1 "$(response "${NS3}:pin")" "$(confirmed "${NS3}")"
expect_posts 4 "a failed POST must be retried next cycle"
grep -q "${NS3}" "${SB}/fleet-founding-pins.json" || fail "a delivered pin must be recorded"

# 6. Forgotten once mdma stops asking, so asking again is answered afresh.
reconcile_founding_pin peer1 "$(response "${NS3}")" "$(confirmed "${NS3}")"
grep -q "${NS3}" "${SB}/fleet-founding-pins.json" && fail "a pin mdma stopped asking for must be forgotten"
reconcile_founding_pin peer1 "$(response "${NS3}:pin")" "$(confirmed "${NS3}")"
expect_posts 5 "a pin asked for again after being dropped must be posted again"

# 7. Never fatal on garbage.
reconcile_founding_pin peer1 "not json" "$(confirmed)" || fail "an unparseable response must not fail the loop"
reconcile_founding_pin peer1 '{"assignments":[{"group_id":"nothex","pin_founding":true}]}' "$(confirmed nothex)" \
  || fail "a malformed group id must not fail the loop"
expect_posts 5 "a malformed pin request must be ignored"

# ========================= legacy verification ==============================
: > "${SB}/post-log"
LEGACY_NS="${NS1}"     # legacyFounding FOUNDER/GENESIS, no founding
namespace "${LEGACY_NS}" "" "${FOUNDER}" "${GENESIS}"
members "${LEGACY_NS}" "${FOUNDER}=Admin" "${ADMIN}=Admin"

# 8. Both fields match: true. Posted to the verification route with the same
#    five-field body as a derived verdict.
reconcile_verification peer1 "$(response "${LEGACY_NS}:${FOUNDER}:${ADMIN}:${GENESIS}")" "$(confirmed "${LEGACY_NS}")"
expect_posts 1 "a legacy question must be answered"
[[ "$(last_url)" == "https://mdma.test/api/fleet/namespaces/${LEGACY_NS}/verification" ]] || fail "route: $(last_url)"
[[ "$(field founder_matches)" == "true" ]] || fail "matching legacy founder and hash must be true: $(last_body)"
[[ "$(field account_role)" == '"Admin"' ]] || fail "account_role: $(last_body)"
keys="$(python3 -c 'import json,sys; print(",".join(sorted(json.loads(sys.argv[1]))))' "$(last_body)")"
[[ "${keys}" == "account_id,account_role,founder_account_id,founder_matches,peer_id" ]] \
  || fail "a legacy verdict must carry the same fields as a derived one, got: ${keys}"
# Dedupe key includes the hash: recorded under a four-part key.
grep -q "${LEGACY_NS}|${FOUNDER}|${ADMIN}|${GENESIS}" "${SB}/fleet-verifications.json" \
  || fail "a legacy verdict must be keyed by its genesis hash: $(cat "${SB}/fleet-verifications.json")"
reconcile_verification peer1 "$(response "${LEGACY_NS}:${FOUNDER}:${ADMIN}:${GENESIS}")" "$(confirmed "${LEGACY_NS}")"
expect_posts 1 "an unchanged legacy verdict must not be re-posted"

# 9. Same founder, different hash: false (a different namespace that founder
#    made must not answer), and a separate question from the one above.
reconcile_verification peer1 "$(response "${LEGACY_NS}:${FOUNDER}:${ADMIN}:${GENESIS2}")" "$(confirmed "${LEGACY_NS}")"
expect_posts 2 "a question with a different genesis hash is a different question"
[[ "$(field founder_matches)" == "false" ]] || fail "a hash mismatch must be false: $(last_body)"
grep -q "${LEGACY_NS}|${FOUNDER}|${ADMIN}|${GENESIS2}" "${SB}/fleet-verifications.json" \
  || fail "the second hash must have its own record"

# 10. Right hash, different founder: false.
reconcile_verification peer1 "$(response "${LEGACY_NS}:${OTHER}:${ADMIN}:${GENESIS}")" "$(confirmed "${LEGACY_NS}")"
expect_posts 3 "a legacy question about another founder must be answered"
[[ "$(field founder_matches)" == "false" ]] || fail "a founder mismatch must be false: $(last_body)"

# 11. legacyFounding present, but the question carries no genesis_op_hash: the
#     derived rule, which legacyFounding can never satisfy. No `founding` here,
#     so false.
reconcile_verification peer1 "$(response "${LEGACY_NS}:${FOUNDER}:${ADMIN}")" "$(confirmed "${LEGACY_NS}")"
expect_posts 4 "a derived question about a legacy namespace must be answered"
[[ "$(field founder_matches)" == "false" ]] || fail "legacyFounding must never satisfy a derived question: $(last_body)"
grep -q "\"${LEGACY_NS}|${FOUNDER}|${ADMIN}\"" "${SB}/fleet-verifications.json" \
  || fail "a derived verdict keeps its three-part key: $(cat "${SB}/fleet-verifications.json")"

# 12. A legacy question is answered from legacyFounding only: a DERIVED
#     namespace whose `founding` names the founder answers false to it.
namespace "${NS2}" "${FOUNDER}"
members "${NS2}" "${ADMIN}=Admin"
reconcile_verification peer1 "$(response "${NS2}:${FOUNDER}:${ADMIN}:${GENESIS}")" "$(confirmed "${NS2}")"
expect_posts 5 "a legacy question about a derived namespace must be answered"
[[ "$(field founder_matches)" == "false" ]] || fail "founding must never answer a legacy question: $(last_body)"
# ...and the derived question about it is still true.
reconcile_verification peer1 "$(response "${NS2}:${FOUNDER}:${ADMIN}")" "$(confirmed "${NS2}")"
expect_posts 6 "the derived question must still be answered"
[[ "$(field founder_matches)" == "true" ]] || fail "the derived rule must be unchanged: $(last_body)"

# 13. A malformed genesis_op_hash drops the question: it is neither answered by
#     the derived rule nor fatal.
reconcile_verification peer1 "$(response "${LEGACY_NS}:${FOUNDER}:${ADMIN}:nothex")" "$(confirmed "${LEGACY_NS}")" \
  || fail "a malformed genesis_op_hash must not fail the loop"
reconcile_verification peer1 '{"assignments":[{"group_id":"'"${LEGACY_NS}"'","verify":{"founder_account_id":"'"${FOUNDER}"'","account_id":"'"${ADMIN}"'","genesis_op_hash":7}}]}' "$(confirmed "${LEGACY_NS}")"
expect_posts 6 "a question with a malformed genesis_op_hash must be dropped"

echo "OK: fleet sidecar legacy founding — 13 checks"
