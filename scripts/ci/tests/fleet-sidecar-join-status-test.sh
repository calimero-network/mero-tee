#!/usr/bin/env bash
# The sidecar tells mdma why a fleet-join did not admit it.
#
# Admission is refused peer to peer, so the cloud used to see only `assigned`
# and the owner had to read the admitter's log. Core's fleet-join answer now
# carries each directly-asked admitter's refusal (`refusals`) or the one that
# said yes (`admitted_by`); the sidecar forwards that to
# `POST /api/fleet/join-status`. The case that motivated it: a node an HA
# disable had removed, refused on every attempt with "was removed from group
# ... and cannot rejoin", while the owner saw nothing.
#
# What fails quietly without this test:
#   * reading `refusals` only from a flat answer, when meroctl wraps it in
#     `{"data": ...}` -- every refusal would be reported as `waiting`;
#   * POSTing on every attempt (a write per ~30 s per namespace), or never
#     again after the first, which freezes the attempt count the owner sees;
#   * a failed POST being remembered as delivered, so mdma never hears it;
#   * the report changing join_group's exit status, which the loop reads as
#     admitted / not admitted;
#   * the outcome getting lost between the worker and the loop: the worker
#     must write no state, so it hands the outcome back in its result line.
#
# Usage: scripts/ci/tests/fleet-sidecar-join-status-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
export SB
mkdir -p "${SB}/bin"

sed -e 's@{{ fleet_mdma_url }}@https://mdma.test@' \
    -e "s@{{ fleet_auth_token | default('') }}@@" \
    -e "s@/run/calimero/fleet-sidecar.log@${SB}/fleet.log@" \
    -e "s@/mnt/data/fleet/@${SB}/@g" \
    -e "s@/mnt/data/tls@${SB}/tls@g" \
    "${TEMPLATE}" > "${SB}/rendered.sh"
sed -n '1,/^# --- Main loop ---$/p' "${SB}/rendered.sh" | sed '$d' > "${SB}/functions.sh"

ADMITTER="12D3KooWOwnerNode"
REMOVED="identity d8c5 was removed from group b42f and cannot rejoin; an admin must re-add them"

# meroctl stub: `tee fleet-join` prints whatever ${SB}/answer holds and exits
# with ${SB}/rc (default 0).
cat > "${SB}/bin/meroctl" <<'STUB'
#!/usr/bin/env bash
case "$*" in
  *"fleet-join --help"*) echo "Usage: meroctl tee fleet-join [--admitter-addr <MULTIADDR>] <GROUP_ID>" ;;
  *"fleet-join"*) cat "${SB}/answer"; exit "$(cat "${SB}/rc" 2>/dev/null || echo 0)" ;;
  *) exit 1 ;;
esac
STUB
# curl stub: records each POST body to ${SB}/posts and fails when ${SB}/down exists.
cat > "${SB}/bin/curl" <<'STUB'
#!/usr/bin/env bash
body="" url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d) body="$2"; shift 2 ;;
    -H|--max-time) shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
[[ -f "${SB}/down" ]] && exit 22
printf '%s %s\n' "${url##*/api/fleet/}" "$body" >> "${SB}/posts"
echo '{"status":"recorded"}'
STUB
chmod +x "${SB}/bin/meroctl" "${SB}/bin/curl"
PATH="${SB}/bin:${PATH}"
export PATH

# shellcheck source=/dev/null
source "${SB}/functions.sh"
# shellcheck disable=SC2034  # read by the sourced sidecar functions
MEROCTL="meroctl"
# shellcheck disable=SC2034
PEER_ID="12D3KooWSelfPeer"

fail() { echo "FAIL: $*" >&2; exit 1; }
# One attempt the way the loop runs it: the join (in the worker, which writes
# nothing), then the report of its outcome (in the loop, which owns the state).
# Returns join_group's status.
attempt() {
  local rc=0
  join_group "$1" >/dev/null 2>&1 || rc=$?
  report_join_status "$1" "$JOIN_OUTCOME" >/dev/null 2>&1 || true
  return "$rc"
}
answer() { printf '%s' "$1" > "${SB}/answer"; }
posts() { [[ -f "${SB}/posts" ]] && wc -l < "${SB}/posts" | tr -d ' ' || echo 0; }
last_post() { tail -n 1 "${SB}/posts"; }
field() { last_post | cut -d' ' -f2- | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)[sys.argv[1]], sort_keys=True))" "$1"; }

REFUSED="{\"data\":{\"admitted\":false,\"refusals\":[{\"peer\":\"${ADMITTER}\",\"reason\":\"${REMOVED}\"}]}}"

# --- a refusal reaches mdma with its reason, through meroctl's wrapper -------
answer "$REFUSED"
if attempt "aa"; then fail "a refused join must still report not-admitted"; fi
[[ "$(posts)" == 1 ]] || fail "the first outcome must be posted once, got $(posts)"
last_post | grep -q '^join-status ' || fail "posted to the wrong endpoint: $(last_post)"
[[ "$(field state)" == '"refused"' ]] || fail "state: $(field state)"
[[ "$(field attempts)" == 1 ]] || fail "attempts: $(field attempts)"
[[ "$(field refusals)" == "[{\"peer\": \"${ADMITTER}\", \"reason\": \"${REMOVED}\"}]" ]] \
  || fail "refusals: $(field refusals)"
[[ "$(field peer_id)" == '"12D3KooWSelfPeer"' ]] || fail "peer_id: $(field peer_id)"

# --- the same outcome again is not re-posted ...------------------------------
attempt "aa" || true
[[ "$(posts)" == 1 ]] || fail "an unchanged outcome must not be re-posted"

# --- ... until JOIN_STATUS_REPORT_EVERY attempts, so the count stays current -
for _ in $(seq 3 "$JOIN_STATUS_REPORT_EVERY"); do attempt "aa" || true; done
[[ "$(posts)" == 2 ]] || fail "attempt ${JOIN_STATUS_REPORT_EVERY} must re-post, got $(posts) posts"
[[ "$(field attempts)" == "$JOIN_STATUS_REPORT_EVERY" ]] || fail "attempts: $(field attempts)"

# --- a change is posted at once ----------------------------------------------
answer '{"admitted":false,"refusals":[]}'
attempt "aa" || true
[[ "$(posts)" == 3 ]] || fail "a changed outcome must be posted"
[[ "$(field state)" == '"waiting"' ]] || fail "no answer from anyone is waiting, got $(field state)"

# --- a failed POST is not remembered as delivered -----------------------------
touch "${SB}/down"
answer "$REFUSED"
attempt "aa" || true
rm -f "${SB}/down"
[[ "$(posts)" == 3 ]] || fail "a refused POST must not be recorded"
attempt "aa" || true
[[ "$(posts)" == 4 ]] || fail "the outcome mdma never got must be posted on the next attempt"
[[ "$(field state)" == '"refused"' ]] || fail "state after retry: $(field state)"

# --- a failed fleet-join is an error, and join_group still returns 1 ---------
answer 'connection refused'
echo 1 > "${SB}/rc"
if attempt "aa"; then fail "a failed fleet-join must return 1"; fi
rm -f "${SB}/rc"
[[ "$(field state)" == '"error"' ]] || fail "state: $(field state)"
field error | grep -q "fleet-join failed" || fail "error: $(field error)"

# --- an admitter said yes, the key is still coming ----------------------------
answer "{\"admitted\":false,\"admitted_by\":\"${ADMITTER}\",\"refusals\":[]}"
attempt "aa" || true
[[ "$(field state)" == '"admitted"' ]] || fail "admitted_by must report admitted, got $(field state)"

# --- admission: reported, join_group returns 0, the record is dropped --------
answer '{"data":{"admitted":true}}'
attempt "aa" || fail "an admitted join must return 0"
python3 -c "import json,sys; sys.exit('aa' in json.load(open(sys.argv[1])))" "${SB}/fleet-join-status.json" \
  || fail "an admitted namespace's record must be dropped"

# --- an older core with no refusals field: waiting, not an error ------------
answer '{"admitted":false,"status":"announced"}'
attempt "bb" || true
[[ "$(field state)" == '"waiting"' ]] || fail "an older core's answer: $(field state)"

# --- the outcome crosses from the worker to the loop -------------------------
answer "$REFUSED"
start_join "cc" ""
for _ in $(seq 100); do join_worker_running || break; sleep 0.1; done
join_finished || true
[[ "$JOIN_DONE_GROUP" == "cc" ]] || fail "collected group: ${JOIN_DONE_GROUP}"
echo "$JOIN_DONE_OUTCOME" | grep -q '"state":"refused"' || fail "outcome lost in the handoff: ${JOIN_DONE_OUTCOME}"
echo "$JOIN_DONE_OUTCOME" | grep -q "cannot rejoin" || fail "reason lost in the handoff: ${JOIN_DONE_OUTCOME}"

echo "PASS: fleet-sidecar join status"
