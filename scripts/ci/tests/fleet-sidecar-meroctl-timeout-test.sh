#!/usr/bin/env bash
# One hung `meroctl` must not stop a node's heartbeat.
#
# The sidecar is one loop, and its should-join poll is the node's ONLY
# heartbeat to mdma. In prod on 2.3.106 a `meroctl tee fleet-join` on
# node-mus85dls never returned: the loop never polled again, every namespace on
# the node went stale in mdma for 40+ minutes, and systemd's `Restart=always`
# did nothing because the process never exited.
#
# Checks (each runs the template's real code against a `meroctl` stub):
#   budget          every `meroctl` call is killed at its budget and the process
#                   is gone; a hung join is a failed join (1), a hung leave is
#                   "outcome unknown" (2), never success.
#   join-heartbeat  while every fleet-join hangs, the poll keeps its 1s cadence,
#                   the join is cut off and retried, and the other namespace
#                   still gets its turn.
#   leave-heartbeat while a due leave hangs, the poll keeps going; the leave is
#                   retried every cycle, stays admitted, keeps its grace timer
#                   and takes no rate-limit stamp.
#   leave-budget    LEAVE_CYCLE_BUDGET bounds the gap between polls when several
#                   due leaves hang, and a namespace whose leave keeps timing out
#                   is tried after the others, so it cannot starve them.
#   help-probe      a `fleet-join --help` probe that times out, or fails, is not
#                   cached as "no --admitter-addr"; the next join probes again,
#                   and only an answer is cached.
#   never-exits     with every meroctl call hanging, failing, or printing
#                   garbage, the sidecar process stays up and keeps polling.
#
# The loop checks run the template's main loop: the function half is sourced as
# the other sidecar tests do, the loop body is cut out of the template, and only
# the collaborators that talk to mdma or walk the tree are stubbed; never-exits
# runs the whole rendered script with only curl and meroctl stubbed.
#
# FLEET_SIDECAR_TEMPLATE runs the checks against another template (a negative
# control against an older build); FLEET_SIDECAR_CHECKS picks which to run.
#
# Usage: scripts/ci/tests/fleet-sidecar-meroctl-timeout-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${FLEET_SIDECAR_TEMPLATE:-${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2}"
CHECKS="${FLEET_SIDECAR_CHECKS:-budget join-heartbeat leave-heartbeat leave-budget help-probe never-exits}"

SB="$(mktemp -d)"
# Kill a process and everything under it (stubs left sleeping by a check).
kill_tree() {
  local child
  for child in $(pgrep -P "$1" 2>/dev/null); do kill_tree "$child"; done
  kill -KILL "$1" 2>/dev/null || true
}
cleanup() {
  if [[ -f "${SB}/hung-pids" ]]; then
    while read -r pid; do kill -KILL "$pid" 2>/dev/null || true; done < "${SB}/hung-pids"
  fi
  if [[ -n "${KEEP_SB:-}" ]]; then echo "kept ${SB}" >&2; return; fi
  rm -rf "${SB}"
}
trap cleanup EXIT
export SB
mkdir -p "${SB}/bin" "${SB}/calimero/default"

fail() { echo "FAIL: $*" >&2; exit 1; }

command -v timeout >/dev/null || fail "coreutils timeout is required (the sidecar depends on it)"
[[ -r "${TEMPLATE}" ]] || fail "cannot read ${TEMPLATE}"

sed -e 's@{{ fleet_mdma_url }}@https://mdma.test@' \
    -e "s@{{ fleet_auth_token | default('') }}@@" \
    -e "s@/run/calimero/fleet-sidecar.log@${SB}/fleet.log@" \
    -e "s@/mnt/data/fleet/@${SB}/@g" \
    -e "s@/mnt/data/calimero@${SB}/calimero@g" \
    -e "s@/mnt/data/tls@${SB}/tls@g" \
    -e "s@/sys/class/misc/tdx_guest@${SB}/tdx@g" \
    -e "s@/etc/calimero/@${SB}/etc-calimero/@g" \
    -e "s@/etc/vector@${SB}/vector@g" \
    -e "s@/etc/vmagent@${SB}/vmagent@g" \
    "${TEMPLATE}" > "${SB}/rendered.sh"
sed -n '1,/^# --- Main loop ---$/p' "${SB}/rendered.sh" | sed '$d' > "${SB}/functions.sh"
sed -n '/^while true; do$/,$p' "${SB}/rendered.sh" > "${SB}/loop.sh"
[[ -s "${SB}/loop.sh" ]] || fail "could not find the main loop in the template"
printf '[identity]\npeer_id = "12D3KooWTimeoutTest"\n' > "${SB}/calimero/default/config.toml"

PATH="${SB}/bin:${PATH}"
export PATH

GA="aa$(printf 'a%.0s' {1..62})"
GB="bb$(printf 'b%.0s' {1..62})"
GC="cc$(printf 'c%.0s' {1..62})"
ns() { printf '%064x\n' "$1"; }

# A meroctl whose join and leave never return, unless the namespace is listed in
# ${SB}/answers (then a leave returns at once). Records each call and its pid,
# then becomes the sleeping process, so the pid is the one `timeout` must kill.
cat > "${SB}/bin/meroctl" <<'STUB'
#!/usr/bin/env bash
args="$*"
last="${*: -1}"
case "${args}" in
  *"fleet-join --help"*)
    echo "${args}" >> "${SB}/help-calls"
    if [[ -e "${SB}/help-hangs" ]]; then
      rm -f "${SB}/help-hangs"
      echo "$$" >> "${SB}/hung-pids"
      exec sleep 300
    fi
    if [[ -e "${SB}/help-fails" ]]; then
      rm -f "${SB}/help-fails"
      echo "error: transport" >&2
      exit 2
    fi
    echo "Usage: meroctl tee fleet-join [--admitter-addr <MULTIADDR>] <GROUP_ID>"
    ;;
  *"fleet-join"*)
    echo "${args}" >> "${SB}/join-calls"
    echo "$$" >> "${SB}/hung-pids"
    exec sleep 300
    ;;
  *"namespace leave"*)
    echo "${last}" >> "${SB}/leave-calls"
    if grep -qx -- "${last}" "${SB}/answers" 2>/dev/null; then
      echo "${last}" >> "${SB}/left"
      echo '{}'
      exit 0
    fi
    echo "$$" >> "${SB}/hung-pids"
    exec sleep 300
    ;;
  *) exit 1 ;;
esac
STUB
chmod +x "${SB}/bin/meroctl"

reset_state() {
  rm -f "${SB}"/fleet-*.json "${SB}"/fleet-*.json.tmp "${SB}/fleet-join.result" \
    "${SB}/join-calls" "${SB}/leave-calls" "${SB}/help-calls" "${SB}/left" "${SB}/answers" \
    "${SB}/help-hangs" "${SB}/help-fails" "${SB}/polls"
  : > "${SB}/fleet.log"
  echo '[]' > "${SB}/fleet-confirmed.json"
  echo '[]' > "${SB}/fleet-admitted.json"
  : > "${SB}/overrides.sh"
}

# Drives the template's real loop body for RUN seconds with every collaborator
# that talks to mdma or walks the tree stubbed; joins and leaves still go
# through the real join worker / join_group / leave_group and the stub above.
cat > "${SB}/harness.sh" <<'HARNESS'
set -euo pipefail
# shellcheck source=/dev/null
source "${SB}/functions.sh"
MEROCTL="meroctl"
MEROCTL_FLEET_JOIN_TIMEOUT=5
MEROCTL_LEAVE_TIMEOUT=2
MEROCTL_KILL_GRACE=1
PEER_ID="12D3KooWSelf"; MRTD=""; EXECUTOR_ACCOUNT="acct"; RELAY_URL=""; SERVER_PORT=2428
LAST_INVENTORY_SCAN=0; LAST_INVENTORY_CONFIRMED=""; LAST_RECOVERY_SCAN=0; LAST_RECOVERY_CONFIRMED=""
reconcile_executor_account() { :; }
reconcile_registration() { :; }
reconcile_login_node_key() { :; }
poll_mdma() { date +%s.%N >> "${SB}/polls"; cat "${SB}/response"; }
read_tee_role() { echo ""; }
confirm_assignment() { return 1; }
reconcile_authorship() { :; }
reconcile_inventory() { :; }
reconcile_recovery() { :; }
# shellcheck source=/dev/null
source "${SB}/overrides.sh"
# shellcheck source=/dev/null
source "${SB}/loop.sh"
HARNESS

run_loop() {
  : > "${SB}/polls"
  timeout -k 2 "$RUN" bash "${SB}/harness.sh" >/dev/null 2>&1 || true
}

# Gaps between consecutive polls, in seconds: prints "<count> <max gap>".
poll_stats() {
  python3 -c '
import sys
ts = [float(l) for l in open(sys.argv[1]) if l.strip()]
gaps = [b - a for a, b in zip(ts, ts[1:])]
print(len(ts), round(max(gaps), 2) if gaps else 0)
' "${SB}/polls"
}
lt() { python3 -c 'import sys; sys.exit(0 if float(sys.argv[1]) < float(sys.argv[2]) else 1)' "$1" "$2"; }
leave_state() {
  python3 -c '
import json, sys
st = json.load(open(sys.argv[1]))
print(json.dumps({"since": st.get("absent_since", {}), "stamps": len(st.get("recent_leaves", []))}, sort_keys=True))
' "${SB}/fleet-leave-pending.json"
}

# --- budget: a single call is killed at its budget --------------------------
check_budget() {
  reset_state
  (
    # shellcheck source=/dev/null
    source "${SB}/functions.sh"
    # shellcheck disable=SC2034  # read by the sourced sidecar functions
    MEROCTL="meroctl"
    # shellcheck disable=SC2034  # read by the sourced sidecar functions
    MEROCTL_KILL_GRACE=1
    start=$(date +%s)
    rc=0
    meroctl_timed 3 tee fleet-join "$GA" >/dev/null 2>&1 || rc=$?
    took=$(( $(date +%s) - start ))
    meroctl_timed_out "$rc" || fail "a hung meroctl exited $rc, not as a timeout"
    (( took <= 5 )) || fail "a 3s budget took ${took}s to enforce"
    [[ -s "${SB}/hung-pids" ]] || fail "the meroctl stub never started (host too loaded?)"
    pid=$(tail -1 "${SB}/hung-pids")
    sleep 0.2
    kill -0 "$pid" 2>/dev/null && fail "the hung meroctl (pid $pid) is still running after its budget"
    [[ "$(meroctl_failure "$rc" 3)" == "timed out after 3s" ]] || fail "meroctl_failure: $(meroctl_failure "$rc" 3)"

    # join_group: a failed join for this namespace, nothing worse.
    # shellcheck disable=SC2034
    MEROCTL_FLEET_JOIN_TIMEOUT=2
    rc=0
    join_group "$GA" >/dev/null 2>&1 || rc=$?
    (( rc == 1 )) || fail "a hung fleet-join should be a failed join (1), got $rc"
    grep -q "fleet-join command failed for $GA (timed out after 2s)" "${SB}/fleet.log" \
      || fail "a timed-out fleet-join is not logged as one"

    # leave_group: outcome unknown, so it must say so (2), not report success.
    # shellcheck disable=SC2034
    MEROCTL_LEAVE_TIMEOUT=2
    rc=0
    leave_group "$GC" >/dev/null 2>&1 || rc=$?
    (( rc == 2 )) || fail "a hung leave must return 2 (retry), got $rc"
  )
  echo "ok: budget"
}

# --- join-heartbeat: the poll never waits on a join -------------------------
# Two assigned namespaces, every join hangs (5s budget each). Long enough for
# the first join to time out and the second to start.
check_join_heartbeat() {
  reset_state
  RUN=15
  printf '{"assignments":[{"group_id":"%s"},{"group_id":"%s"}]}\n' "$GA" "$GB" > "${SB}/response"
  run_loop
  read -r polls max_gap <<<"$(poll_stats)"
  echo "   joins hanging: ${polls} polls in ${RUN}s, longest gap ${max_gap}s"
  (( polls >= RUN / 3 )) \
    || fail "only ${polls} polls in ${RUN}s while fleet-join hangs; the join is blocking the heartbeat"
  lt "$max_gap" 3 || fail "the poll stalled for ${max_gap}s while a fleet-join hung; it should keep its 1s cadence"
  grep -q "$GA" "${SB}/join-calls" || fail "no fleet-join was attempted for the first namespace"
  grep -q "$GB" "${SB}/join-calls" \
    || fail "the second namespace never got a join while the first kept timing out"
  grep -q "timed out after 5s" "${SB}/fleet.log" || fail "the hung join was never cut off at its budget"
  [[ "$(cat "${SB}/fleet-admitted.json")" == "[]" ]] || fail "a timed-out join must not be recorded as admitted"
  echo "ok: join-heartbeat"
}

# --- leave-heartbeat: a hung leave is retried, not recorded -----------------
# A namespace whose leave grace period has run out, and the leave hangs (2s
# budget). Leaves run inline, so each cycle costs one leave budget: slower, but
# never stopped. The timed-out leave is retried every cycle, stays admitted,
# keeps its grace timer as it was (no fresh 24h), and takes no rate-limit stamp:
# it has not been left.
check_leave_heartbeat() {
  reset_state
  RUN=16
  echo '{"assignments":[]}' > "${SB}/response"
  printf '["%s"]\n' "$GC" > "${SB}/fleet-admitted.json"
  local since
  since=$(( $(date +%s) - 86400 - 10 ))
  printf '{"absent_since": {"%s": %s}, "deferred": [], "recent_leaves": [], "suspicious": false}\n' \
    "$GC" "$since" > "${SB}/fleet-leave-pending.json"
  run_loop
  read -r polls max_gap <<<"$(poll_stats)"
  echo "   leave hanging: ${polls} polls in ${RUN}s, longest gap ${max_gap}s"
  (( polls >= 3 )) || fail "only ${polls} polls in ${RUN}s while the leave hangs"
  lt "$max_gap" 6 || fail "the poll stalled ${max_gap}s behind a hung leave; it is bounded by its budget"
  local leaves
  leaves=$(grep -c "$GC" "${SB}/leave-calls" || true)
  (( leaves >= 2 )) || fail "a timed-out leave was not retried (${leaves} attempts)"
  grep -q "$GC" "${SB}/fleet-admitted.json" \
    || fail "a leave that timed out was dropped from the admitted set, so it is never retried"
  grep -q "timed out after 2s; outcome unknown" "${SB}/fleet.log" || fail "the hung leave is not logged as one"
  grep -q "Namespace $GC is no longer assigned by mdma" "${SB}/fleet.log" \
    && fail "a timed-out leave restarted its grace period instead of being retried"
  [[ "$(leave_state)" == "{\"since\": {\"$GC\": $since}, \"stamps\": 0}" ]] \
    || fail "${leaves} timed-out attempts at one leave changed the leave state: $(leave_state)"
  echo "ok: leave-heartbeat"
}

# --- leave-budget: LEAVE_CYCLE_BUDGET bounds the gap, slow leaves go last ----
# Four due leaves (the rate limit allows four), five kept namespaces so the
# drop is not a mass drop. Two of the leaves hang (2s budget each); the other
# two return at once. With a 3s cycle budget a cycle starts at most two hung
# leaves, so no poll gap reaches the 8s that four back-to-back hung leaves
# would cost; and the two that keep hanging are tried after the two that
# return, so those are left even though they are the younger absences.
check_leave_budget() {
  reset_state
  RUN=14
  echo 'LEAVE_CYCLE_BUDGET=3' > "${SB}/overrides.sh"
  local c1 c2 c3 c4 k now
  c1=$(ns 1); c2=$(ns 2); c3=$(ns 3); c4=$(ns 4)
  local kept=()
  for k in 11 12 13 14 15; do kept+=("$(ns "$k")"); done
  python3 -c 'import json,sys; print(json.dumps({"assignments": [{"group_id": g} for g in sys.argv[1:]]}))' \
    "${kept[@]}" > "${SB}/response"
  python3 -c 'import json,sys; print(json.dumps(sorted(sys.argv[1:])))' "${kept[@]}" > "${SB}/fleet-confirmed.json"
  python3 -c 'import json,sys; print(json.dumps(sorted(sys.argv[1:])))' "$c1" "$c2" "$c3" "$c4" "${kept[@]}" \
    > "${SB}/fleet-admitted.json"
  now=$(date +%s)
  # c1 and c2 are the oldest absences, so plan order puts them first.
  python3 -c '
import json, sys
now, grace = int(sys.argv[1]), 86400
since = {sys.argv[2]: now - grace - 400, sys.argv[3]: now - grace - 300,
         sys.argv[4]: now - grace - 200, sys.argv[5]: now - grace - 100}
print(json.dumps({"absent_since": since, "deferred": [], "recent_leaves": [], "suspicious": False}))
' "$now" "$c1" "$c2" "$c3" "$c4" > "${SB}/fleet-leave-pending.json"
  printf '%s\n%s\n' "$c3" "$c4" > "${SB}/answers"
  local before
  before=$(python3 -c 'import json,sys; s=json.load(open(sys.argv[1]))["absent_since"]; print(s[sys.argv[2]], s[sys.argv[3]])' \
    "${SB}/fleet-leave-pending.json" "$c1" "$c2")
  run_loop
  read -r polls max_gap <<<"$(poll_stats)"
  echo "   four due leaves, two hanging: ${polls} polls in ${RUN}s, longest gap ${max_gap}s"
  (( polls >= 3 )) || fail "only ${polls} polls in ${RUN}s while leaves hang"
  # Budget 3s + one leave's 2s budget + its 1s kill grace, plus scheduling.
  lt "$max_gap" 6.5 || fail "a ${max_gap}s gap between polls: LEAVE_CYCLE_BUDGET is not bounding the leave step"
  grep -q "Leave budget (3s) spent this cycle" "${SB}/fleet.log" \
    || fail "no cycle ever ran out of leave budget, so the bound was not exercised"
  if ! grep -qx "$c3" "${SB}/left" || ! grep -qx "$c4" "${SB}/left"; then
    fail "the two leaves that return were starved by the two that keep hanging: left '$(tr '\n' ' ' < "${SB}/left" 2>/dev/null)'"
  fi
  local a1 a2
  a1=$(grep -cx "$c1" "${SB}/leave-calls" || true)
  a2=$(grep -cx "$c2" "${SB}/leave-calls" || true)
  (( a1 >= 2 && a2 >= 2 )) || fail "the hanging leaves were not retried (${a1}, ${a2} attempts)"
  python3 -c '
import json, sys
adm = set(json.load(open(sys.argv[1])))
c1, c2, c3, c4 = sys.argv[2:6]
if not {c1, c2} <= adm:
    sys.exit("a timed-out leave was dropped from the admitted set")
if adm & {c3, c4}:
    sys.exit("a leave that returned is still admitted")
st = json.load(open(sys.argv[6]))
since = st["absent_since"]
if set(since) & {c3, c4}:
    sys.exit(f"a leave that returned kept its grace timer: {since}")
if f"{since.get(c1)} {since.get(c2)}" != sys.argv[7]:
    sys.exit(f"timed-out leaves changed their grace timers: {since}")
stamps = st["recent_leaves"]
if len(stamps) != 2:
    sys.exit(f"want 2 rate-limit stamps (the leaves that returned), got {stamps}")
' "${SB}/fleet-admitted.json" "$c1" "$c2" "$c3" "$c4" "${SB}/fleet-leave-pending.json" "$before" \
    || fail "leave bookkeeping is wrong after a budget-bounded cycle"
  echo "ok: leave-budget"
}

# --- help-probe: a timed-out probe is not cached ----------------------------
check_help_probe() {
  reset_state
  touch "${SB}/help-hangs"
  # shellcheck disable=SC2016  # expanded by the inner shell
  timeout -k 2 30 bash -c '
    set -euo pipefail
    fail() { echo "FAIL: $*" >&2; exit 1; }
    # shellcheck source=/dev/null
    source "${SB}/functions.sh"
    MEROCTL="meroctl"
    MEROCTL_PROBE_TIMEOUT=2
    MEROCTL_KILL_GRACE=1
    rc=0
    fleet_join_takes_admitters >/dev/null || rc=$?
    (( rc != 0 )) || fail "a probe that timed out reported --admitter-addr support"
    [[ -z "${FLEET_JOIN_TAKES_ADMITTERS}" ]] \
      || fail "a probe that timed out was cached as \"${FLEET_JOIN_TAKES_ADMITTERS}\"; every later join would skip it"
    grep -q "help timed out after 2s" "${SB}/fleet.log" || fail "the timed-out probe is not logged as one"
    # A probe that fails outright is not an answer either.
    touch "${SB}/help-fails"
    rc=0
    fleet_join_takes_admitters >/dev/null || rc=$?
    (( rc != 0 )) || fail "a probe that failed reported --admitter-addr support"
    [[ -z "${FLEET_JOIN_TAKES_ADMITTERS}" ]] \
      || fail "a probe that failed (rc=2) was cached as \"${FLEET_JOIN_TAKES_ADMITTERS}\""
    fleet_join_takes_admitters >/dev/null || fail "the probe after a failure did not find --admitter-addr"
    [[ "${FLEET_JOIN_TAKES_ADMITTERS}" == "yes" ]] || fail "an answered probe was not cached"
    fleet_join_takes_admitters >/dev/null || fail "the cached answer was lost"
    [[ "$(wc -l < "${SB}/help-calls")" -eq 3 ]] \
      || fail "want 3 probes (timed out, failed, answered), got $(wc -l < "${SB}/help-calls")"
  ' || fail "help-probe (exit $?; 124 means a probe hung the caller)"
  echo "ok: help-probe"
}

# --- never-exits: no meroctl outcome ends the loop --------------------------
# The whole rendered script, with every meroctl call (peers included) cycling
# through: hang until killed, ignore TERM until KILLed, exit 1, exit 2, exit 124,
# exit 137, and garbage on stdout with exit 0. The process must still be up at
# the end and still polling.
check_never_exits() {
  reset_state
  local chaos="${SB}/chaos-bin"
  mkdir -p "$chaos"
  cat > "${chaos}/meroctl" <<'STUB'
#!/usr/bin/env bash
n=$(( $(cat "${SB}/chaos-n" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "${SB}/chaos-n"
echo "$*" >> "${SB}/chaos-calls"
case $(( n % 7 )) in
  0) echo "$$" >> "${SB}/hung-pids"; exec sleep 300 ;;
  1) trap '' TERM; echo "$$" >> "${SB}/hung-pids"; sleep 300 ;;
  2) exit 1 ;;
  3) echo "error: no" >&2; exit 2 ;;
  4) exit 124 ;;
  5) exit 137 ;;
  *) echo '{"admitted": tru'; exit 0 ;;
esac
STUB
  cat > "${chaos}/curl" <<'STUB'
#!/usr/bin/env bash
for a in "$@"; do
  if [[ "$a" == https://mdma.test/api/fleet/should-join ]]; then
    date +%s.%N >> "${SB}/polls"
    cat "${SB}/should-join"
    exit 0
  fi
done
exit 22
STUB
  chmod +x "${chaos}/meroctl" "${chaos}/curl"
  echo "test-token" > "${SB}/fleet-token"
  local k1 k2 g1 g2 now
  k1=$(ns 21); k2=$(ns 22); g1=$(ns 31); g2=$(ns 32)
  local kept=()
  for k in 41 42 43 44 45; do kept+=("$(ns "$k")"); done
  python3 -c 'import json,sys; print(json.dumps({"assignments": [{"group_id": g} for g in sys.argv[1:]]}))' \
    "$g1" "$g2" "${kept[@]}" > "${SB}/should-join"
  # Admitted but not confirmed: they keep the drop below the mass-drop guard
  # without starting the (separately budgeted) inventory and recovery walks,
  # which would otherwise take most of the run.
  python3 -c 'import json,sys; print(json.dumps(sorted(sys.argv[1:])))' "$k1" "$k2" "${kept[@]}" > "${SB}/fleet-admitted.json"
  now=$(date +%s)
  printf '{"absent_since": {"%s": %s, "%s": %s}, "deferred": [], "recent_leaves": [], "suspicious": false}\n' \
    "$k1" "$(( now - 86400 - 20 ))" "$k2" "$(( now - 86400 - 10 ))" > "${SB}/fleet-leave-pending.json"
  # Small budgets so a 30s run sees every kind of call fail many times.
  sed -e 's/^MEROCTL_KILL_GRACE=.*/MEROCTL_KILL_GRACE=1/' \
      -e 's/^MEROCTL_FLEET_JOIN_TIMEOUT=.*/MEROCTL_FLEET_JOIN_TIMEOUT=3/' \
      -e 's/^MEROCTL_LEAVE_TIMEOUT=.*/MEROCTL_LEAVE_TIMEOUT=2/' \
      -e 's/^MEROCTL_SEAL_TIMEOUT=.*/MEROCTL_SEAL_TIMEOUT=2/' \
      -e 's/^MEROCTL_READ_TIMEOUT=.*/MEROCTL_READ_TIMEOUT=2/' \
      -e 's/^MEROCTL_PROBE_TIMEOUT=.*/MEROCTL_PROBE_TIMEOUT=2/' \
      -e 's/^MEROD_WAIT_TIMEOUT=.*/MEROD_WAIT_TIMEOUT=6/' \
      -e 's/^INVENTORY_WALK_BUDGET=.*/INVENTORY_WALK_BUDGET=3/' \
      -e 's/^LEAVE_CYCLE_BUDGET=.*/LEAVE_CYCLE_BUDGET=3/' \
      "${SB}/rendered.sh" > "${SB}/chaos.sh"
  : > "${SB}/polls"
  PATH="${chaos}:${PATH}" bash "${SB}/chaos.sh" >/dev/null 2>&1 &
  local pid=$! t=0
  while (( t < 40 )); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 1
    t=$(( t + 1 ))
  done
  local alive=no
  kill -0 "$pid" 2>/dev/null && alive=yes
  kill_tree "$pid"
  wait "$pid" 2>/dev/null || true
  local calls polls recent
  calls=$(wc -l < "${SB}/chaos-calls" 2>/dev/null || echo 0)
  read -r polls _ <<<"$(poll_stats)"
  recent=$(python3 -c '
import sys, time
ts = [float(l) for l in open(sys.argv[1]) if l.strip()]
print(sum(1 for t in ts if t > time.time() - 15))' "${SB}/polls")
  echo "   chaos meroctl: ${calls} meroctl calls, ${polls} polls in ${t}s, ${recent} in the last 15s"
  [[ "$alive" == "yes" ]] \
    || fail "the sidecar exited after ${t}s of failing meroctl calls: $(tail -3 "${SB}/fleet.log")"
  (( polls >= 6 )) || fail "only ${polls} polls in ${t}s with a failing meroctl"
  (( recent >= 2 )) || fail "the sidecar stopped polling (${recent} polls in its last 15s)"
  (( calls >= 10 )) || fail "only ${calls} meroctl calls: the chaos stub was barely exercised"
  echo "ok: never-exits"
}

for check in ${CHECKS}; do
  "check_${check//-/_}"
done

echo "PASS: a hung meroctl is cut off at its budget and never stops the poll"
