#!/usr/bin/env bash
# Behavioural test for the fleet sidecar's namespace-admin verification.
#
# mdma lets any CURRENT admin of a namespace enable HA, and it cannot check who
# that is: admin-ness is governance state readable only inside the group's key.
# So a `should-join` assignment may carry
#   "verify": {"founder_account_id": ..., "account_id": ...}
# and this node, once confirmed in the namespace, answers
#   POST /api/fleet/namespaces/<ns>/verification
#   {"peer_id", "founder_account_id", "account_id", "founder_matches", "account_role"}
#
# Every way this is wrong is quiet:
#   * "not a member" read off a TRUNCATED member page is a false verdict about a
#     real admin;
#   * a verdict recorded before mdma acknowledged it is lost for good;
#   * re-posting an unchanged verdict writes to mdma once a second;
#   * NOT re-posting a changed one strands a real admin: mdma lets only a
#     positive verdict decide, and a just-joined node's first answer may come
#     from governance that has not synced yet (or a merod with no `founding`);
#   * a body carrying anything beyond the verdict leaks the membership the
#     inventory is careful never to send;
#   * a malformed `verify` that reached the poll gate would fail every poll,
#     which is the leave path's safety gate.
#
# Same harness as fleet-sidecar-authorship-test.sh: render the template, source
# the function half, drive it against stubbed `meroctl` and `curl`.
#
# Usage: scripts/ci/tests/fleet-sidecar-verification-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
export SB

fail() { echo "FAIL: $*" >&2; exit 1; }

[[ -r "${TEMPLATE}" ]] || fail "cannot read ${TEMPLATE}"

# --- render the template ---------------------------------------------------
# `@` as the delimiter: the auth-token placeholder contains a Jinja filter pipe.
# The state directory is redirected wholesale, so a state file added later
# cannot silently escape the sandbox.
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

# The loop must actually call it, after the join and the prune: a function that
# is only ever called by this test answers nothing in production.
#
# The patterns below name the loop's own shell variables literally, so they are
# single-quoted on purpose.
loop="$(sed -n '/^# --- Main loop ---$/,$p' "${SB}/rendered.sh")"
# shellcheck disable=SC2016
grep -q 'reconcile_verification "\$PEER_ID" "\$response" "\$confirmed"' <<< "${loop}" \
  || fail "the main loop does not call reconcile_verification over the confirmed set"
# shellcheck disable=SC2016
prune_line="$(grep -n 'save_confirmed "\$confirmed"' <<< "${loop}" | head -1 | cut -d: -f1)"
# shellcheck disable=SC2016
call_line="$(grep -n 'reconcile_verification "\$PEER_ID"' <<< "${loop}" | head -1 | cut -d: -f1)"
(( call_line > prune_line )) || fail "reconcile_verification must run after the confirmed prune"

# --- stubs -----------------------------------------------------------------
mkdir -p "${SB}/bin" "${SB}/ns" "${SB}/members"

# `meroctl`: `namespace get <ns>` from ${SB}/ns/<ns> (missing file = the command
# fails), `group members list <ns>` from ${SB}/members/<ns>. Every call is
# appended to ${SB}/meroctl-log so a test can assert nothing was read.
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

# `curl`: records "<url> <token header> <body>" per POST to ${SB}/post-log, or
# fails while ${SB}/post-fails exists.
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
echo '{}'
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
NS1="$(hex a)"; NS2="$(hex b)"; NS3="$(hex c)"; NS4="$(hex d)"; NS5="$(hex e)"
FOUNDER="$(hex 1)"; ADMIN="$(hex 2)"; OTHER="$(hex 3)"; STRANGER="$(hex 4)"

posts() { awk 'NF{n++} END{print n+0}' "${SB}/post-log"; }
expect_posts() {
  local want="$1" why="$2" got
  got="$(posts)"
  [[ "${got}" == "${want}" ]] || fail "${why} (expected ${want} posts, got ${got}): $(cat "${SB}/post-log")"
}
last_body() { tail -1 "${SB}/post-log" | cut -f3; }
field() { python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1])[sys.argv[2]]))' "$(last_body)" "$1"; }

# A should-join response. Each arg is "<ns>" or "<ns>:<founder>:<account>".
response() {
  python3 -c '
import json, sys
out = []
for arg in sys.argv[1:]:
    parts = arg.split(":")
    entry = {"group_id": parts[0], "admitter_addrs": []}
    if len(parts) == 3:
        entry["verify"] = {"founder_account_id": parts[1], "account_id": parts[2]}
    out.append(entry)
print(json.dumps({"assignments": out}))' "$@"
}
confirmed() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "$@"; }

# namespace fixture: founded by $2, or no founding at all when $2 is empty.
namespace() {
  python3 -c '
import json, sys
data = {"namespaceId": sys.argv[1], "memberCount": 2}
if sys.argv[2]:
    data["founding"] = {"founderAccountId": sys.argv[2].upper(), "salt": "00" * 32}
print(json.dumps({"data": data}))' "$1" "${2:-}" > "${SB}/ns/$1"
}
# member fixture: "<account>=<role>" args, padded with $PAD filler members.
members() {
  local ns="$1"; shift
  PAD="${PAD:-0}" python3 -c '
import json, os, sys
rows = [{"identity": a, "role": r} for a, r in (arg.split("=") for arg in sys.argv[1:])]
rows += [{"identity": "%064x" % (i + 1), "role": "Member"} for i in range(int(os.environ["PAD"]))]
print(json.dumps({"members": rows}))' "$@" > "${SB}/members/${ns}"
}

# 1. Founder matches and the account is an Admin: one post, to the namespace's
#    verification route, with the fleet token, carrying exactly the verdict.
namespace "${NS1}" "${FOUNDER}"
members "${NS1}" "${FOUNDER}=Admin" "${ADMIN}=Admin" "${OTHER}=ReadOnlyTee"
reconcile_verification peer1 "$(response "${NS1}:${FOUNDER}:${ADMIN}")" "$(confirmed "${NS1}")"
expect_posts 1 "a confirmed namespace carrying verify must be answered"
[[ "$(tail -1 "${SB}/post-log" | cut -f1)" == "https://mdma.test/api/fleet/namespaces/${NS1}/verification" ]] \
  || fail "posted to the wrong route: $(tail -1 "${SB}/post-log" | cut -f1)"
[[ "$(tail -1 "${SB}/post-log" | cut -f2)" == "X-Fleet-Token: f1.peer1.sig" ]] \
  || fail "the verification POST must carry the fleet token"
[[ "$(field founder_matches)" == "true" ]] || fail "founder_matches: $(last_body)"
[[ "$(field account_role)" == '"Admin"' ]] || fail "account_role: $(last_body)"
[[ "$(field peer_id)" == '"peer1"' ]] || fail "peer_id: $(last_body)"
[[ "$(field account_id)" == "\"${ADMIN}\"" ]] || fail "account_id: $(last_body)"
[[ "$(field founder_account_id)" == "\"${FOUNDER}\"" ]] || fail "founder_account_id: $(last_body)"
# PRIVACY: exactly the five contract fields -- no roster, no other account.
keys="$(python3 -c 'import json,sys; print(",".join(sorted(json.loads(sys.argv[1]))))' "$(last_body)")"
[[ "${keys}" == "account_id,account_role,founder_account_id,founder_matches,peer_id" ]] \
  || fail "the verification body must carry only the verdict fields, got: ${keys}"
grep -q "${OTHER}" "${SB}/post-log" && fail "an account mdma did not name crossed the wire"

# 2. The same question with the same answer: posted once, not once a second.
#    It IS re-read (that is how a changed answer is noticed), just not re-sent.
: > "${SB}/meroctl-log"
reconcile_verification peer1 "$(response "${NS1}:${FOUNDER}:${ADMIN}")" "$(confirmed "${NS1}")"
reconcile_verification peer1 "$(response "${NS1}:${FOUNDER}:${ADMIN}")" "$(confirmed "${NS1}")"
expect_posts 1 "an unchanged answer must not be re-posted"
grep -q "namespace get ${NS1}" "${SB}/meroctl-log" || fail "a pending question must be re-read to notice a change"

# 3. No founding on this replica (V1 genesis, or a forged one): false. Still a
#    verdict, still posted.
namespace "${NS2}" ""
members "${NS2}" "${ADMIN}=Admin"
reconcile_verification peer1 "$(response "${NS2}:${FOUNDER}:${ADMIN}")" "$(confirmed "${NS2}")"
expect_posts 2 "an absent founding is a verdict"
[[ "$(field founder_matches)" == "false" ]] || fail "absent founding must be false: $(last_body)"
[[ "$(field account_role)" == '"Admin"' ]] || fail "role is independent of founding: $(last_body)"

# ...and a DIFFERENT founder is false too.
namespace "${NS2}" "${OTHER}"
reconcile_verification peer1 "$(response "${NS2}:${FOUNDER}:${OTHER}")" "$(confirmed "${NS2}")"
expect_posts 3 "a new question about the same namespace must be answered"
[[ "$(field founder_matches)" == "false" ]] || fail "a different founder must be false: $(last_body)"

# 4. The account is not a member (complete list): account_role null.
namespace "${NS3}" "${FOUNDER}"
members "${NS3}" "${FOUNDER}=Admin" "${OTHER}=Member"
reconcile_verification peer1 "$(response "${NS3}:${FOUNDER}:${STRANGER}")" "$(confirmed "${NS3}")"
expect_posts 4 "a non-member is a verdict when the list is complete"
[[ "$(field account_role)" == "null" ]] || fail "a non-member must be null: $(last_body)"
[[ "$(field founder_matches)" == "true" ]] || fail "founder_matches: $(last_body)"

# 5. A member list at the page limit WITHOUT the account: nothing posted,
#    nothing recorded, one warning (not one per cycle).
namespace "${NS4}" "${FOUNDER}"
PAD=100 members "${NS4}"
warned_before="$(grep -c 'cannot verify' "${SB}/fleet.log" || true)"
reconcile_verification peer1 "$(response "${NS4}:${FOUNDER}:${ADMIN}")" "$(confirmed "${NS4}")"
reconcile_verification peer1 "$(response "${NS4}:${FOUNDER}:${ADMIN}")" "$(confirmed "${NS4}")"
expect_posts 4 "a truncated member list must never report 'not a member'"
grep -q "${NS4}" "${SB}/fleet-verifications.json" && fail "an unanswered question must not be recorded"
warned_after="$(grep -c 'cannot verify' "${SB}/fleet.log" || true)"
(( warned_after - warned_before == 1 )) \
  || fail "a persistently unanswerable question must warn once, got $(( warned_after - warned_before ))"

# ...but the account FOUND on a truncated page is a certain answer.
PAD=99 members "${NS4}" "${ADMIN}=Member"
reconcile_verification peer1 "$(response "${NS4}:${FOUNDER}:${ADMIN}")" "$(confirmed "${NS4}")"
expect_posts 5 "a member found on a full page is a certain answer"
[[ "$(field account_role)" == '"Member"' ]] || fail "role on a full page: $(last_body)"

# 6. An unreadable namespace (merod not answering, not yet synced): no post.
members "${NS5}" "${ADMIN}=Admin"
reconcile_verification peer1 "$(response "${NS5}:${FOUNDER}:${ADMIN}")" "$(confirmed "${NS5}")"
expect_posts 5 "an unreadable founding must not be reported as false"

# 7. A failed POST is not recorded, and is retried on the next cycle.
namespace "${NS5}" "${FOUNDER}"
touch "${SB}/post-fails"
reconcile_verification peer1 "$(response "${NS5}:${FOUNDER}:${ADMIN}")" "$(confirmed "${NS5}")"
rm -f "${SB}/post-fails"
grep -q "${NS5}" "${SB}/fleet-verifications.json" && fail "a failed POST must not be recorded"
reconcile_verification peer1 "$(response "${NS5}:${FOUNDER}:${ADMIN}")" "$(confirmed "${NS5}")"
expect_posts 6 "a failed POST must be retried next cycle"
grep -q "${NS5}" "${SB}/fleet-verifications.json" || fail "a delivered verdict must be recorded"

# 8. No verify, or not confirmed yet: no call at all, merod not even asked.
: > "${SB}/meroctl-log"
reconcile_verification peer1 "$(response "${NS1}" "${NS3}")" "$(confirmed "${NS1}" "${NS3}")"
expect_posts 6 "an assignment without verify must not be verified"
reconcile_verification peer1 "$(response "${NS2}:${FOUNDER}:${STRANGER}")" "$(confirmed)"
expect_posts 6 "a namespace not yet confirmed has nothing to answer from"
[[ ! -s "${SB}/meroctl-log" ]] || fail "no verify / unconfirmed must not touch merod: $(cat "${SB}/meroctl-log")"

# 9. Forgotten once mdma stops asking, so a later identical question is
#    answered afresh. (Every reconcile prunes to the questions in THAT response,
#    so NS1's record from case 1 is already gone; re-establish it first.)
q1="$(response "${NS1}:${FOUNDER}:${ADMIN}")"
reconcile_verification peer1 "${q1}" "$(confirmed "${NS1}")"
reconcile_verification peer1 "${q1}" "$(confirmed "${NS1}")"
expect_posts 7 "re-establishing NS1's verdict posts once"
grep -q "${NS1}" "${SB}/fleet-verifications.json" || fail "NS1's verdict must be recorded"
reconcile_verification peer1 "$(response "${NS1}")" "$(confirmed "${NS1}")"
grep -q "${NS1}" "${SB}/fleet-verifications.json" && fail "a question mdma stopped asking must be forgotten"
reconcile_verification peer1 "${q1}" "$(confirmed "${NS1}")"
expect_posts 8 "a question asked again after being dropped must be answered again"

# 10. A malformed verify is ignored and never fatal: it must
#     never reach merod or mdma.
bad='{"assignments":[{"group_id":"'"${NS3}"'","verify":{"founder_account_id":"nothex","account_id":7}},{"group_id":"'"${NS3}"'","verify":"yes"}]}'
reconcile_verification peer1 "${bad}" "$(confirmed "${NS3}")" || fail "a malformed verify must not fail the loop"
expect_posts 8 "a malformed verify must be ignored"
reconcile_verification peer1 "not json" "$(confirmed)" || fail "an unparseable response must not fail the loop"

# 11. The answer improves: re-posted once per CHANGE. A just-joined replica
#     has not synced the account yet (null), then governance lands (Admin); the
#     same answer twice more stays at one post each. Then a merod upgrade makes
#     `founding` appear (false -> true), which is a change too.
: > "${SB}/post-log"
q3="$(response "${NS3}:${FOUNDER}:${ADMIN}")"
namespace "${NS3}" ""
members "${NS3}" "${FOUNDER}=Admin"
reconcile_verification peer1 "${q3}" "$(confirmed "${NS3}")"
reconcile_verification peer1 "${q3}" "$(confirmed "${NS3}")"
expect_posts 1 "the same (null) answer twice must post once"
[[ "$(field account_role)" == "null" ]] || fail "unsynced: $(last_body)"
members "${NS3}" "${FOUNDER}=Admin" "${ADMIN}=Admin"
reconcile_verification peer1 "${q3}" "$(confirmed "${NS3}")"
reconcile_verification peer1 "${q3}" "$(confirmed "${NS3}")"
expect_posts 2 "null then Admin must post twice, and the repeat Admin not at all"
[[ "$(field account_role)" == '"Admin"' ]] || fail "synced: $(last_body)"
[[ "$(field founder_matches)" == "false" ]] || fail "no founding yet: $(last_body)"
namespace "${NS3}" "${FOUNDER}"
reconcile_verification peer1 "${q3}" "$(confirmed "${NS3}")"
reconcile_verification peer1 "${q3}" "$(confirmed "${NS3}")"
expect_posts 3 "founding appearing after an upgrade must be reported once"
[[ "$(field founder_matches)" == "true" ]] || fail "upgraded: $(last_body)"
# An answer that becomes unreadable again is not a change: nothing posted, and
# the last delivered verdict stays on record.
rm -f "${SB}/ns/${NS3}"
reconcile_verification peer1 "${q3}" "$(confirmed "${NS3}")"
expect_posts 3 "an unreadable answer must not be posted as a change"
grep -q '"founder_matches": true' "${SB}/fleet-verifications.json" \
  || fail "an unreadable cycle must keep the last delivered verdict: $(cat "${SB}/fleet-verifications.json")"

echo "OK: fleet sidecar namespace verification — 11 checks, $(posts) verdicts posted"
