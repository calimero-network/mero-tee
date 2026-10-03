#!/usr/bin/env bash
# One should-join answer must never purge a fleet node's namespaces.
#
# `meroctl namespace leave` publishes MemberLeft and core purges this node's
# keys and data for the namespace: it cannot be undone. The sidecar used to run
# it for every admitted namespace the moment mdma stopped listing it, so a
# compromised mdma, or any well-formed `{"assignments": []}` (a policy omitting
# this image's measurements, an image-profile edit, a plan downgrade), made
# every replica purge every namespace within one poll.
#
# This runs the WHOLE rendered sidecar -- the real main loop, not a copy of its
# decision -- against stubbed `meroctl`, `curl`, `date` and `sleep`, restarting
# it between phases the way systemd would, and pins:
#
#   * an empty answer leaves nothing (the regression this test was written for);
#   * a namespace is left only after LEAVE_GRACE_SECONDS of continuous absence;
#   * the grace survives a restart (it is on disk, not in memory);
#   * a namespace that reappears clears its timer;
#   * `retain` keeps a namespace without assigning it;
#   * a drop of most namespaces at once leaves nothing, even past the grace;
#   * at most LEAVE_MAX_PER_WINDOW leaves per LEAVE_RATE_WINDOW;
#   * the admitted set loses only what was actually left;
#   * an unreadable state file restarts the grace rather than skipping it;
#   * a leave that times out (outcome unknown) stays admitted with its timer
#     untouched, is retried every cycle and across restarts without a fresh
#     grace, takes NO rate-limit stamp until a leave for it returns, and only
#     then is counted and forgotten.
#
# Usage: scripts/ci/tests/fleet-sidecar-leave-grace-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
export SB

fail() { echo "FAIL: $*" >&2; exit 1; }

[[ -r "${TEMPLATE}" ]] || fail "cannot read ${TEMPLATE}"

sed -e 's@{{ fleet_mdma_url }}@https://mdma.test@' \
    -e "s@/run/calimero/fleet-sidecar.log@${SB}/fleet.log@" \
    -e "s@/mnt/data/fleet/@${SB}/@g" \
    -e "s@/mnt/data/calimero@${SB}/calimero@g" \
    -e "s@/sys/class/misc/tdx_guest@${SB}/tdx@g" \
    -e "s@/etc/calimero/@${SB}/etc-calimero/@g" \
    -e "s@/etc/vector@${SB}/vector@g" \
    -e "s@/etc/vmagent@${SB}/vmagent@g" \
    "${TEMPLATE}" > "${SB}/rendered.sh"
if grep -q '{{\|{%' "${SB}/rendered.sh"; then
  grep -n '{{\|{%' "${SB}/rendered.sh" >&2
  fail "unsubstituted Jinja left in the rendered sidecar"
fi

mkdir -p "${SB}/bin" "${SB}/calimero/default"
printf '[identity]\npeer_id = "12D3KooWLeaveGraceTest"\n' > "${SB}/calimero/default/config.toml"
echo "test-token" > "${SB}/fleet-token"

# --- stubs -----------------------------------------------------------------
# `curl`: should-join answers ${SB}/should-join; everything else fails, which
# every other reconcile treats as "try again later".
cat > "${SB}/bin/curl" <<'STUB'
#!/usr/bin/env bash
for a in "$@"; do
  if [[ "${a}" == https://mdma.test/api/fleet/should-join ]]; then
    cat "${SB}/should-join"
    exit 0
  fi
done
exit 22
STUB
# `meroctl`: merod is up; every leave is recorded; everything else fails. A
# namespace listed in ${SB}/hang has its leave "time out": exit 124, which is
# what `timeout` reports when it kills a call that ran out of budget.
cat > "${SB}/bin/meroctl" <<'STUB'
#!/usr/bin/env bash
args=" $* "
if [[ "${args}" == *" peers "* ]]; then echo '{}'; exit 0; fi
if [[ "${args}" == *" namespace leave "* ]]; then
  echo "${*: -1}" >> "${SB}/attempts"
  if grep -qx -- "${*: -1}" "${SB}/hang" 2>/dev/null; then exit 124; fi
  echo "${*: -1}" >> "${SB}/left"
  echo '{}'
  exit 0
fi
exit 1
STUB
# `date +%s` is the test's clock; any other form is the real date.
cat > "${SB}/bin/date" <<'STUB'
#!/usr/bin/env bash
if [[ "$*" == "+%s" ]]; then cat "${SB}/now"; exit 0; fi
exec /bin/date "$@"
STUB
# `sleep`: the loop's only pause. Stops the sidecar after ${SB}/cycles of them,
# as systemd stopping the unit would.
cat > "${SB}/bin/sleep" <<'STUB'
#!/usr/bin/env bash
n=$(( $(cat "${SB}/sleeps" 2>/dev/null || echo 0) + 1 ))
echo "${n}" > "${SB}/sleeps"
if (( n >= $(cat "${SB}/cycles") )); then
  until [[ -s "${SB}/pid" ]]; do /bin/sleep 0.1; done
  kill -TERM "$(cat "${SB}/pid")"
fi
exit 0
STUB
chmod +x "${SB}/bin/"*
PATH="${SB}/bin:${PATH}"
export PATH

ns() { printf '%064x\n' "$1"; }
A="$(ns 1)" B="$(ns 2)" C="$(ns 3)" D="$(ns 4)" E="$(ns 5)" F="$(ns 6)"
NOW=1700000000
GRACE="$(sed -n 's/^LEAVE_GRACE_SECONDS=\([0-9][0-9]*\)$/\1/p' "${SB}/rendered.sh")"
[[ -n "${GRACE}" ]] || GRACE=86400

# Answer should-join with these assignments (and an optional retain list).
answer() {
  local retain="${RETAIN:-}"
  python3 -c '
import json, sys
retain = [g for g in sys.argv[1].split(",") if g]
body = {"assignments": [{"group_id": g, "context_id": ""} for g in sys.argv[2:]]}
if retain:
    body["retain"] = retain
print(json.dumps(body))' "${retain}" "$@" > "${SB}/should-join"
}
# Run the sidecar for N loop cycles at the given clock, as a fresh process.
run() {
  echo "$2" > "${SB}/now"
  echo "$1" > "${SB}/cycles"
  : > "${SB}/sleeps"
  : > "${SB}/pid"
  bash "${SB}/rendered.sh" > /dev/null 2>&1 &
  echo "$!" > "${SB}/pid"
  wait "$!" 2> /dev/null || true
}
left() { sort "${SB}/left" 2>/dev/null | tr '\n' ' ' | sed 's/ $//'; }
admitted() { python3 -c 'import json,sys; print(" ".join(sorted(json.load(open(sys.argv[1])))))' "${SB}/fleet-admitted.json"; }
holds() { [[ " $(admitted) " == *" $1 "* ]]; }
# A node that already holds these namespaces, from a previous tenure.
hold() {
  python3 -c 'import json,sys; print(json.dumps(sorted(sys.argv[1:])))' "$@" > "${SB}/fleet-admitted.json"
  cp "${SB}/fleet-admitted.json" "${SB}/fleet-confirmed.json"
  rm -f "${SB}/left" "${SB}/attempts" "${SB}/hang" "${SB}/fleet-leave-pending.json"
  : > "${SB}/fleet.log"
}

# --- 1. THE FINDING: one empty answer purges nothing -----------------------
hold "${A}" "${B}" "${C}" "${D}"
answer
run 3 "${NOW}"
[[ -z "$(left)" ]] || fail "an empty should-join answer made the node leave: $(left)"
for g in "${A}" "${B}" "${C}" "${D}"; do
  holds "${g}" || fail "an empty answer dropped ${g} from the admitted set; its leave would be forgotten"
done
grep -q 'ALERT: should-join dropped 4 of 4' "${SB}/fleet.log" \
  || fail "a mass drop was not logged loudly"

# ... and not even once the grace period has passed: the guard needs the answer
# to stop looking like a mass drop.
run 2 $(( NOW + GRACE * 3 ))
[[ -z "$(left)" ]] || fail "a mass drop was acted on once the grace passed: $(left)"

# --- 2. a single dropped namespace waits out the grace ---------------------
hold "${A}" "${B}" "${C}" "${D}"
answer "${B}" "${C}" "${D}"
run 2 "${NOW}"
[[ -z "$(left)" ]] || fail "a namespace was left on the first poll that omitted it: $(left)"
holds "${A}" || fail "a namespace inside its grace was dropped from the admitted set"
grep -q "Namespace ${A} is no longer assigned by mdma" "${SB}/fleet.log" \
  || fail "the start of a grace period was not logged"

# A restart one second short of the grace: the clock is on disk, so it neither
# restarts (which would be safe but wrong) nor is skipped.
run 2 $(( NOW + GRACE - 1 ))
[[ -z "$(left)" ]] || fail "a namespace was left before its grace period ended: $(left)"

run 2 $(( NOW + GRACE ))
[[ "$(left)" == "${A}" ]] || fail "expected exactly ${A} left after the grace, got '$(left)'"
holds "${A}" && fail "a namespace that was left is still in the admitted set"
for g in "${B}" "${C}" "${D}"; do
  holds "${g}" || fail "leaving ${A} dropped ${g} from the admitted set"
done
run 2 $(( NOW + GRACE + 10 ))
[[ "$(left)" == "${A}" ]] || fail "a namespace was left twice: '$(left)'"

# --- 3. reappearing clears the timer ---------------------------------------
hold "${A}" "${B}" "${C}" "${D}"
answer "${B}" "${C}" "${D}"
run 2 "${NOW}"
answer "${A}" "${B}" "${C}" "${D}"
run 2 $(( NOW + 100 ))
grep -q "Namespace ${A} is listed by mdma again" "${SB}/fleet.log" \
  || fail "a cancelled leave was not logged"
answer "${B}" "${C}" "${D}"
run 2 $(( NOW + GRACE + 1 ))
[[ -z "$(left)" ]] || fail "a namespace that reappeared kept its old timer and was left: $(left)"
run 2 $(( NOW + 2 * GRACE + 1 ))
[[ "$(left)" == "${A}" ]] || fail "a fresh absence after a reappearance never completed: '$(left)'"

# --- 4. `retain` keeps a namespace without assigning it --------------------
hold "${A}" "${B}" "${C}" "${D}"
RETAIN="${A}" answer "${B}" "${C}" "${D}"
run 2 "${NOW}"
run 2 $(( NOW + GRACE * 2 ))
[[ -z "$(left)" ]] || fail "a namespace mdma asked to retain was left: $(left)"
holds "${A}" || fail "a retained namespace was dropped from the admitted set"
# Retaining everything is not a mass drop.
RETAIN="${A},${B},${C},${D}" answer
run 2 $(( NOW + GRACE * 4 ))
[[ -z "$(left)" ]] || fail "retaining every namespace left one: $(left)"
# A malformed retain fails the whole poll instead of being ignored.
python3 -c 'import json; print(json.dumps({"assignments": [], "retain": ["nope"]}))' > "${SB}/should-join"
run 2 $(( NOW + GRACE * 6 ))
[[ -z "$(left)" ]] || fail "a malformed retain list was acted on: $(left)"

# --- 5. the rate limit -----------------------------------------------------
# Six of eighteen dropped (a third: not a mass drop), all past their grace at
# once. Four go in the first window, the other two only once it has rolled.
kept=()
for i in $(seq 7 18); do kept+=("$(ns "${i}")"); done
hold "${A}" "${B}" "${C}" "${D}" "${E}" "${F}" "${kept[@]}"
answer "${kept[@]}"
run 2 "${NOW}"
run 2 $(( NOW + GRACE ))
[[ "$(left | wc -w)" -eq 4 ]] || fail "expected 4 leaves in the first window, got '$(left)'"
grep -q 'Leave rate limit (4 per 3600s) reached' "${SB}/fleet.log" \
  || fail "deferring leaves to the rate limit was not logged"
run 2 $(( NOW + GRACE + 1800 ))
[[ "$(left | wc -w)" -eq 4 ]] || fail "the rate limit did not hold for the whole window: '$(left)'"
run 2 $(( NOW + GRACE + 3600 ))
[[ "$(left | wc -w)" -eq 6 ]] || fail "the deferred leaves did not complete once the window rolled: '$(left)'"
for g in "${A}" "${B}" "${C}" "${D}" "${E}" "${F}"; do
  holds "${g}" && fail "${g} was left but is still admitted"
done

# --- 6. an unreadable state file restarts the grace ------------------------
hold "${A}" "${B}" "${C}" "${D}"
answer "${B}" "${C}" "${D}"
run 2 "${NOW}"
echo 'not json' > "${SB}/fleet-leave-pending.json"
run 2 $(( NOW + GRACE ))
[[ -z "$(left)" ]] || fail "a corrupt state file let a leave through without a full grace: $(left)"
grep -q 'leave state unreadable' "${SB}/fleet.log" || fail "a corrupt state file was not logged"
run 2 $(( NOW + 2 * GRACE ))
[[ "$(left)" == "${A}" ]] || fail "after a corrupt state file the leave never completed: '$(left)'"

# --- 7. a leave that times out is retried, not restarted or counted -------
# meroctl_timed reports a call that ran out of budget as 124, leave_group turns
# that into "outcome unknown", and the namespace must stay admitted and be
# issued again -- with its timer untouched (its grace already ran out; a fresh
# 24h would be wrong) and no rate-limit stamp (it has not been left; counting
# every retry would let one slow namespace use up the window and hold every
# other leave back). Once a leave for it returns it is counted, once, and
# forgotten.
attempts() { grep -c -- "$1" "${SB}/attempts" 2>/dev/null || echo 0; }
stamps() { python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1])).get("recent_leaves", [])))' "${SB}/fleet-leave-pending.json"; }
since_of() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("absent_since", {}).get(sys.argv[2], "none"))' "${SB}/fleet-leave-pending.json" "$1"; }
hold "${A}" "${B}" "${C}" "${D}"
answer "${B}" "${C}" "${D}"
run 2 "${NOW}"
[[ "$(since_of "${A}")" == "${NOW}" ]] || fail "the grace timer did not start at ${NOW}: $(since_of "${A}")"
echo "${A}" > "${SB}/hang"
: > "${SB}/fleet.log"
run 3 $(( NOW + GRACE ))
(( $(attempts "${A}") >= 2 )) || fail "a timed-out leave was not retried in the next cycle ($(attempts "${A}") attempts)"
grep -q "namespace leave for ${A} timed out" "${SB}/fleet.log" || fail "the timed-out leave is not logged as one"
[[ -z "$(left)" ]] || fail "a timed-out leave was recorded as left: $(left)"
holds "${A}" || fail "a timed-out leave was dropped from the admitted set, so it is never retried"
grep -q "Namespace ${A} is no longer assigned by mdma" "${SB}/fleet.log" \
  && fail "a timed-out leave started a fresh grace period instead of being retried"
[[ "$(since_of "${A}")" == "${NOW}" ]] || fail "a timed-out leave changed its grace timer: $(since_of "${A}")"
[[ "$(stamps)" -eq 0 ]] || fail "$(attempts "${A}") timed-out attempts at a leave took $(stamps) rate-limit stamps, not 0"
# Across a restart, still hanging: issued again at once, still not counted.
before="$(attempts "${A}")"
run 3 $(( NOW + GRACE + 60 ))
(( $(attempts "${A}") > before )) || fail "a timed-out leave was not resumed after a restart"
[[ "$(stamps)" -eq 0 ]] || fail "timed-out retries across a restart took $(stamps) rate-limit stamps"
[[ "$(since_of "${A}")" == "${NOW}" ]] || fail "a restart changed a timed-out leave's timer: $(since_of "${A}")"
holds "${A}" || fail "a timed-out leave was dropped from the admitted set after a restart"
# merod answers again: the leave completes, is counted once, and only now is
# it forgotten -- from the admitted set and from the pending timers.
rm -f "${SB}/hang"
run 3 $(( NOW + GRACE + 120 ))
[[ "$(left)" == "${A}" ]] || fail "the retried leave never completed: '$(left)'"
holds "${A}" && fail "a namespace whose retried leave completed is still admitted"
[[ "$(stamps)" -eq 1 ]] || fail "a completed leave took $(stamps) rate-limit stamps, not 1"
[[ "$(since_of "${A}")" == "none" ]] || fail "a completed leave kept its grace timer: $(since_of "${A}")"
before="$(attempts "${A}")"
run 2 $(( NOW + GRACE + 180 ))
[[ "$(attempts "${A}")" -eq "${before}" ]] || fail "a completed leave was issued again"

# A timed-out leave does not hold the others back: with a slow namespace
# hanging all window long, the other three due leaves still go through.
hold "${A}" "${B}" "${C}" "${D}" "${kept[@]}"
answer "${kept[@]}"
run 2 "${NOW}"
echo "${A}" > "${SB}/hang"
run 4 $(( NOW + GRACE ))
[[ "$(left)" == "${B} ${C} ${D}" ]] || fail "a hanging leave held the others back: left '$(left)'"
[[ "$(stamps)" -eq 3 ]] || fail "expected 3 stamps (the leaves that returned), got $(stamps)"
holds "${A}" || fail "the hanging leave was dropped from the admitted set"

# A timed-out leave whose namespace mdma lists again is not retried.
hold "${A}" "${B}" "${C}" "${D}"
answer "${B}" "${C}" "${D}"
run 2 "${NOW}"
echo "${A}" > "${SB}/hang"
run 2 $(( NOW + GRACE ))
answer "${A}" "${B}" "${C}" "${D}"
before="$(attempts "${A}")"
run 2 $(( NOW + GRACE + 60 ))
[[ "$(attempts "${A}")" -eq "${before}" ]] || fail "a namespace mdma lists again still had its timed-out leave retried"
grep -q "Namespace ${A} is listed by mdma again; its pending leave is cancelled" "${SB}/fleet.log" \
  || fail "cancelling a timed-out leave on reappearance was not logged"
holds "${A}" || fail "a namespace mdma lists again was dropped from the admitted set"

echo "PASS: fleet-sidecar leaves only after a grace period, never en masse, at a bounded rate, and retries a timed-out leave"
