#!/usr/bin/env bash
# The background fleet-join worker and its handshake with the loop.
#
# `fleet-join` runs in a background worker so the should-join poll (the node's
# only heartbeat to mdma) never waits on it. The loop starts at most one worker,
# collects its result on a later cycle, and does every state write itself:
# note_admitted, /confirm, the confirmed set. The worker hands its result over
# in one file, renamed into place, tagged with the launch it belongs to and the
# namespace it was for.
#
# Checks:
#   collect-confirm      a join that takes a while is collected on a later
#                        cycle; the poll keeps its cadence meanwhile; the
#                        namespace is recorded admitted and /confirm is sent
#                        from the loop's own process, once.
#   dropped-mid-join     a join that admits after mdma stopped assigning the
#                        namespace is still recorded as admitted, is NOT
#                        confirmed, starts the grace timer, and is left by the
#                        grace-gated leave once that has run out.
#   watchdog             a worker that outlives JOIN_WATCHDOG is killed with
#                        everything under it, the namespace is retried, and the
#                        poll never stalls.
#   one-worker           never two joins at once; the namespaces take turns.
#   stale-garbled        only the result of the launch being waited for is
#                        taken: a result from another launch (an older worker,
#                        a previous sidecar process) is ignored, a garbled or
#                        truncated one is a failed join, an unrenamed temporary
#                        file is not a result, and a worker gone without a
#                        result is a failed join.
#   worker-writes-nothing the worker leaves every state file byte-for-byte as
#                        it found it, admitted, timed out or refused; only the
#                        loop writes state.
#
# The loop checks run the whole rendered sidecar with curl and meroctl stubbed;
# the handshake checks source its function half, as the other sidecar tests do.
#
# FLEET_SIDECAR_TEMPLATE runs the checks against another template (a negative
# control against an older build); FLEET_SIDECAR_CHECKS picks which to run.
#
# Usage: scripts/ci/tests/fleet-sidecar-join-worker-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${FLEET_SIDECAR_TEMPLATE:-${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2}"
CHECKS="${FLEET_SIDECAR_CHECKS:-collect-confirm dropped-mid-join watchdog one-worker stale-garbled worker-writes-nothing}"

SB="$(mktemp -d)"
# Stub bookkeeping lives in ${T}, apart from the sidecar's own state in ${SB}.
T="${SB}/t"
kill_tree() {
  local child
  for child in $(pgrep -P "$1" 2>/dev/null); do kill_tree "$child"; done
  kill -KILL "$1" 2>/dev/null || true
}
cleanup() {
  if [[ -f "${T}/hung-pids" ]]; then
    while read -r pid; do kill -KILL "$pid" 2>/dev/null || true; done < "${T}/hung-pids"
  fi
  if [[ -n "${KEEP_SB:-}" ]]; then echo "kept ${SB}" >&2; return; fi
  rm -rf "${SB}"
}
trap cleanup EXIT
export SB T
mkdir -p "${SB}/bin" "${SB}/calimero/default" "${T}"

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
if grep -q '{{\|{%' "${SB}/rendered.sh"; then
  grep -n '{{\|{%' "${SB}/rendered.sh" >&2
  fail "unsubstituted Jinja left in the rendered sidecar"
fi
sed -n '1,/^# --- Main loop ---$/p' "${SB}/rendered.sh" | sed '$d' > "${SB}/functions.sh"
printf '[identity]\npeer_id = "12D3KooWJoinWorkerTest"\n' > "${SB}/calimero/default/config.toml"

# --- stubs -----------------------------------------------------------------
# `curl`: should-join answers ${T}/should-join and stamps ${T}/polls; /confirm
# succeeds and records "<pid of the caller's parent> <body>"; the rest fails.
cat > "${SB}/bin/curl" <<'STUB'
#!/usr/bin/env bash
body=""
prev=""
for a in "$@"; do
  [[ "${prev}" == "-d" ]] && body="${a}"
  prev="${a}"
done
for a in "$@"; do
  case "${a}" in
    https://mdma.test/api/fleet/should-join)
      date +%s.%N >> "${T}/polls"
      cat "${T}/should-join"
      exit 0 ;;
    https://mdma.test/api/fleet/confirm)
      echo "${PPID} ${body}" >> "${T}/confirms"
      echo '{}'
      exit 0 ;;
  esac
done
exit 22
STUB
# `meroctl`: merod is up, the probe finds --admitter-addr, leaves succeed, and a
# fleet-join does what ${T}/join-mode says:
#   admit-after N        wait N seconds, then report admitted
#   refuse-after N       wait N seconds, then report not admitted
#   admit-after-drop N   mdma stops assigning everything, then as admit-after
#   hang                 never return
#   locked-hang          never return; and record an overlap if another join
#                        is already running
cat > "${SB}/bin/meroctl" <<'STUB'
#!/usr/bin/env bash
args=" $* "
last="${*: -1}"
case "${args}" in
  *" peers "*) echo '{}'; exit 0 ;;
  *" fleet-join --help "*)
    echo "Usage: meroctl tee fleet-join [--admitter-addr <MULTIADDR>] <GROUP_ID>"; exit 0 ;;
  *" namespace leave "*) echo "${last}" >> "${T}/leave-calls"; echo '{}'; exit 0 ;;
  *" tee fleet-join "*) ;;
  *) exit 1 ;;
esac
group=""
prev=""
for a in "$@"; do
  [[ "${prev}" == "fleet-join" ]] && group="${a}"
  prev="${a}"
done
echo "${group} $$" >> "${T}/join-calls"
read -r mode secs < "${T}/join-mode"
case "${mode}" in
  admit-after-drop)
    echo '{"assignments": []}' > "${T}/should-join"
    sleep "${secs}"; echo '{"admitted": true}' ;;
  admit-after) sleep "${secs}"; echo '{"admitted": true}' ;;
  refuse-after) sleep "${secs}"; echo '{"admitted": false}' ;;
  hang) echo "$$" >> "${T}/hung-pids"; exec sleep 300 ;;
  locked-hang)
    if ! mkdir "${T}/inflight" 2>/dev/null; then echo "${group}" >> "${T}/overlaps"; fi
    trap 'rmdir "${T}/inflight" 2>/dev/null; kill "${child}" 2>/dev/null; exit 143' TERM
    sleep 300 &
    child=$!
    echo "${child}" >> "${T}/hung-pids"
    wait ;;
esac
STUB
chmod +x "${SB}/bin/"*
PATH="${SB}/bin:${PATH}"
export PATH

ns() { printf '%064x\n' "$1"; }
G1="$(ns 1)" G2="$(ns 2)" G3="$(ns 3)"
GRACE="$(sed -n 's/^LEAVE_GRACE_SECONDS=\([0-9][0-9]*\)$/\1/p' "${SB}/rendered.sh")"
[[ -n "${GRACE}" ]] || GRACE=86400

reset_state() {
  find "${SB}" -maxdepth 1 -name 'fleet-*' -exec rm -f {} +
  rm -rf "${T}" && mkdir -p "${T}"
  : > "${SB}/fleet.log"
  echo "test-token" > "${SB}/fleet-token"
  echo '[]' > "${SB}/fleet-confirmed.json"
  echo '[]' > "${SB}/fleet-admitted.json"
}
answer() {
  python3 -c 'import json,sys; print(json.dumps({"assignments": [{"group_id": g, "context_id": ""} for g in sys.argv[1:]]}))' \
    "$@" > "${T}/should-join"
}
# Render with a fleet-join budget and, optionally, a watchdog.
render() {
  local expr=(-e 's/^MEROCTL_KILL_GRACE=.*/MEROCTL_KILL_GRACE=1/'
              -e "s/^MEROCTL_FLEET_JOIN_TIMEOUT=.*/MEROCTL_FLEET_JOIN_TIMEOUT=$1/")
  if [[ -n "${2:-}" ]]; then expr+=(-e "s/^JOIN_WATCHDOG=.*/JOIN_WATCHDOG=$2/"); fi
  sed "${expr[@]}" "${SB}/rendered.sh" > "${SB}/run.sh"
}
# Run the sidecar for N seconds of wall clock, then stop it and everything
# under it, as systemd stopping the unit would.
run_sidecar() {
  : > "${T}/polls"
  bash "${SB}/run.sh" > /dev/null 2>&1 &
  SIDECAR_PID=$!
  sleep "$1"
  kill_tree "${SIDECAR_PID}"
  wait "${SIDECAR_PID}" 2>/dev/null || true
}
max_gap() {
  python3 -c '
import sys
ts = [float(l) for l in open(sys.argv[1]) if l.strip()]
gaps = [b - a for a, b in zip(ts, ts[1:])]
print(round(max(gaps), 2) if gaps else 99)
' "${T}/polls"
}
lt() { python3 -c 'import sys; sys.exit(0 if float(sys.argv[1]) < float(sys.argv[2]) else 1)' "$1" "$2"; }
in_json() { python3 -c 'import json,sys; sys.exit(0 if sys.argv[1] in json.load(open(sys.argv[2])) else 1)' "$1" "$2"; }
count() { grep -c -- "$1" "$2" 2>/dev/null || true; }

# --- collect-confirm --------------------------------------------------------
check_collect_confirm() {
  reset_state
  render 90
  answer "$G1"
  echo "admit-after 3" > "${T}/join-mode"
  run_sidecar 9
  local gap polls
  gap=$(max_gap); polls=$(wc -l < "${T}/polls")
  echo "   a 3s join: ${polls} polls in 9s, longest gap ${gap}s"
  lt "$gap" 2.5 || fail "the poll stalled ${gap}s while a join was running; it must not wait on the worker"
  [[ "$(count "$G1" "${T}/join-calls")" -eq 1 ]] \
    || fail "want exactly one fleet-join for $G1, got $(count "$G1" "${T}/join-calls")"
  in_json "$G1" "${SB}/fleet-admitted.json" || fail "the collected admission was not recorded in the admitted set"
  in_json "$G1" "${SB}/fleet-confirmed.json" || fail "the collected admission was not confirmed"
  [[ "$(count "\"group_id\":\"$G1\"" "${T}/confirms")" -eq 1 ]] \
    || fail "want one /confirm for $G1, got $(count "\"group_id\":\"$G1\"" "${T}/confirms")"
  [[ "$(cut -d' ' -f1 "${T}/confirms")" == "${SIDECAR_PID}" ]] \
    || fail "/confirm was sent by pid $(cut -d' ' -f1 "${T}/confirms"), not by the loop (${SIDECAR_PID})"
  [[ ! -e "${SB}/fleet-join.result" ]] || fail "a collected result was left behind"
  echo "ok: collect-confirm"
}

# --- dropped-mid-join -------------------------------------------------------
check_dropped_mid_join() {
  reset_state
  render 90
  answer "$G1"
  echo "admit-after-drop 3" > "${T}/join-mode"
  run_sidecar 8
  in_json "$G1" "${SB}/fleet-admitted.json" \
    || fail "an admission that landed after mdma dropped the namespace was not recorded; it could never be left"
  in_json "$G1" "${SB}/fleet-confirmed.json" && fail "a namespace mdma no longer assigns was confirmed"
  [[ "$(count "$G1" "${T}/confirms")" -eq 0 ]] || fail "/confirm was sent for a namespace mdma no longer assigns"
  grep -q "Admitted into $G1 after mdma stopped assigning it" "${SB}/fleet.log" \
    || fail "the late admission is not logged"
  [[ ! -s "${T}/leave-calls" ]] || fail "a namespace was left inside its grace period"
  python3 -c '
import json, sys
st = json.load(open(sys.argv[1]))
if sys.argv[2] not in st.get("absent_since", {}):
    sys.exit("no grace timer was started for the late admission")
' "${SB}/fleet-leave-pending.json" "$G1" || fail "the late admission is not pending a leave"

  # Its grace runs out: the grace-gated leave takes it.
  python3 -c '
import json, sys, time
p = sys.argv[1]
st = json.load(open(p))
st["absent_since"][sys.argv[2]] = int(time.time()) - int(sys.argv[3]) - 10
json.dump(st, open(p, "w"))
' "${SB}/fleet-leave-pending.json" "$G1" "$GRACE"
  echo "refuse-after 0" > "${T}/join-mode"
  run_sidecar 4
  [[ "$(count "$G1" "${T}/leave-calls")" -eq 1 ]] \
    || fail "the late admission was not left once its grace ran out ($(count "$G1" "${T}/leave-calls") leaves)"
  in_json "$G1" "${SB}/fleet-admitted.json" && fail "a namespace that was left is still admitted"
  python3 -c '
import json, sys
st = json.load(open(sys.argv[1]))
if sys.argv[2] in st.get("absent_since", {}) or len(st.get("recent_leaves", [])) != 1:
    sys.exit(f"leave state after the leave: {st}")
' "${SB}/fleet-leave-pending.json" "$G1" || fail "the completed leave was not recorded"
  echo "ok: dropped-mid-join"
}

# --- watchdog ---------------------------------------------------------------
check_watchdog() {
  reset_state
  # A join budget far beyond the watchdog, so only the watchdog can end it.
  render 60 3
  answer "$G1"
  echo "hang" > "${T}/join-mode"
  run_sidecar 10
  local gap first
  gap=$(max_gap)
  echo "   a wedged worker: $(count "$G1" "${T}/join-calls") joins in 10s, longest poll gap ${gap}s"
  grep -q "fleet-join worker for $G1 still running after 3s; killing it" "${SB}/fleet.log" \
    || fail "the watchdog never fired on a wedged worker"
  first=$(head -1 "${T}/hung-pids")
  kill -0 "$first" 2>/dev/null && fail "the first wedged join (pid $first) is still running after the watchdog"
  (( $(count "$G1" "${T}/join-calls") >= 2 )) || fail "the namespace was not retried after the watchdog"
  lt "$gap" 2.5 || fail "the poll stalled ${gap}s around a wedged worker"
  echo "ok: watchdog"
}

# --- one-worker -------------------------------------------------------------
check_one_worker() {
  reset_state
  render 2
  answer "$G1" "$G2" "$G3"
  echo "locked-hang" > "${T}/join-mode"
  run_sidecar 12
  local joins groups
  joins=$(wc -l < "${T}/join-calls")
  groups=$(cut -d' ' -f1 "${T}/join-calls" | sort -u | wc -l)
  echo "   three pending, every join hanging: ${joins} joins over ${groups} namespaces"
  [[ ! -s "${T}/overlaps" ]] || fail "two fleet-joins ran at once: $(tr '\n' ' ' < "${T}/overlaps")"
  (( joins >= 3 )) || fail "only ${joins} joins in 12s with a 2s budget"
  (( groups == 3 )) || fail "the pending namespaces did not take turns: only ${groups} of 3 were tried"
  echo "ok: one-worker"
}

# --- stale-garbled ----------------------------------------------------------
check_stale_garbled() {
  reset_state
  # shellcheck disable=SC2016  # expanded by the inner shell
  timeout -k 2 90 bash -c '
    set -euo pipefail
    fail() { echo "FAIL: $*" >&2; exit 1; }
    # shellcheck source=/dev/null
    source "${SB}/functions.sh"
    MEROCTL="meroctl"
    MEROCTL_KILL_GRACE=1
    MEROCTL_FLEET_JOIN_TIMEOUT=10
    G1="$1" G2="$2"
    R="${JOIN_RESULT_FILE}"
    settle() {
      local i=0
      while join_worker_running && (( i < 100 )); do sleep 0.1; i=$(( i + 1 )); done
      ! join_worker_running || fail "a worker did not finish"
    }
    # In this shell, not a $(...): collecting changes the loop'"'"'s variables.
    collect() { COLLECTED=0; join_finished || COLLECTED=$?; }

    # Control: a worker that admits is collected as admitted, and cleaned up.
    echo "admit-after 0" > "${T}/join-mode"
    start_join "$G1" ""
    settle
    collect; [[ "$COLLECTED" == 0 ]] || fail "an admitting worker was not collected as admitted"
    [[ "$JOIN_DONE_GROUP" == "$G1" ]] || fail "collected for \"$JOIN_DONE_GROUP\", not $G1"
    [[ ! -e "$R" ]] || fail "the collected result was left behind"
    [[ -z "$JOIN_PID" ]] || fail "the worker slot was not freed"

    # A result from another launch saying "admitted", written while ours runs
    # (our join will be refused): ignored while ours runs, and after it.
    echo "refuse-after 2" > "${T}/join-mode"
    start_join "$G1" ""
    printf "999-1-1 0 %s\n" "$G1" > "$R"
    collect; [[ "$COLLECTED" == 1 ]] || fail "a stale admitted result was taken while our join was still running"
    [[ -n "$JOIN_PID" ]] || fail "a stale result ended the wait for our own"
    settle
    collect; [[ "$COLLECTED" == 1 ]] || fail "our refused join was collected as admitted"

    # The same, landing AFTER ours (a straggler overwriting it): still not ours.
    echo "refuse-after 0" > "${T}/join-mode"
    start_join "$G1" ""
    settle
    printf "999-1-1 0 %s\n" "$G1" > "$R"
    collect; [[ "$COLLECTED" == 1 ]] || fail "a straggler'"'"'s admitted result was taken for ours"
    grep -q "ended without a result (ignored a result from launch 999-1-1)" "${SB}/fleet.log" \
      || fail "the ignored straggler result is not logged"

    # A stale refusal does not hide our admission.
    echo "admit-after 1" > "${T}/join-mode"
    start_join "$G1" ""
    printf "999-1-1 1 %s\n" "$G1" > "$R"
    collect; [[ "$COLLECTED" == 1 ]] || fail "collected while our join was still running"
    settle
    collect; [[ "$COLLECTED" == 0 ]] || fail "our admission was lost behind a stale result"

    # Garbled or truncated results that carry our launch id: a failed join.
    echo "admit-after 0" > "${T}/join-mode"
    for shape in "%s 0" "%s 0 $G2" "%s zero $G1" "%s 0 $G1 extra" "%s" "%s -1 $G1"; do
      start_join "$G1" ""
      settle
      # shellcheck disable=SC2059  # the shape is the format, on purpose
      printf "$shape\n" "$JOIN_ID" > "$R"
      collect; [[ "$COLLECTED" == 1 ]] || fail "a garbled result (\"$(cat "$R" 2>/dev/null)\" shape \"$shape\") was taken as admitted"
    done
    grep -q "unreadable fleet-join result for $G1" "${SB}/fleet.log" || fail "a garbled result is not logged"

    # Written but never renamed (worker killed between the two): not a result.
    start_join "$G1" ""
    settle
    id="$JOIN_ID"
    rm -f "$R"
    printf "%s 0 %s\n" "$id" "$G1" > "${R}.${id}.tmp"
    collect; [[ "$COLLECTED" == 1 ]] || fail "an unrenamed temporary file was taken as a result"

    # Gone without any result: a failed join, logged, slot freed.
    start_join "$G1" ""
    settle
    rm -f "$R"
    collect; [[ "$COLLECTED" == 1 ]] || fail "a worker gone without a result was collected as admitted"
    [[ -z "$JOIN_PID" ]] || fail "a worker gone without a result kept the slot"
    grep -q "fleet-join worker for $G1 ended without a result; will retry" "${SB}/fleet.log" \
      || fail "a worker gone without a result is not logged"
  ' _ "$G1" "$G2" >/dev/null || fail "stale-garbled (exit $?)"
  echo "ok: stale-garbled"
}

# --- worker-writes-nothing --------------------------------------------------
check_worker_writes_nothing() {
  reset_state
  printf '["%s"]\n' "$G2" > "${SB}/fleet-confirmed.json"
  printf '["%s", "%s"]\n' "$G2" "$G3" > "${SB}/fleet-admitted.json"
  printf '{"absent_since": {"%s": 1}, "deferred": [], "recent_leaves": [5], "suspicious": false}\n' \
    "$G3" > "${SB}/fleet-leave-pending.json"
  printf '{"%s": "ReadOnlyTee"}\n' "$G2" > "${SB}/fleet-authorship.json"
  # shellcheck disable=SC2016  # expanded by the inner shell
  timeout -k 2 60 bash -c '
    set -euo pipefail
    fail() { echo "FAIL: $*" >&2; exit 1; }
    # shellcheck source=/dev/null
    source "${SB}/functions.sh"
    MEROCTL="meroctl"
    MEROCTL_KILL_GRACE=1
    MEROCTL_FLEET_JOIN_TIMEOUT=2
    G1="$1"
    # Every file in the state directory but the log, with content and mtime.
    snap() {
      python3 -c "
import hashlib, os, sys
d = sys.argv[1]
for n in sorted(os.listdir(d)):
    p = os.path.join(d, n)
    if not os.path.isfile(p) or n == \"fleet.log\":
        continue
    st = os.stat(p)
    print(n, st.st_mtime_ns, hashlib.sha256(open(p, \"rb\").read()).hexdigest())
" "$SB"
    }
    settle() {
      local i=0
      while join_worker_running && (( i < 100 )); do sleep 0.1; i=$(( i + 1 )); done
    }
    for mode in "admit-after 1" "refuse-after 0" "hang"; do
      echo "$mode" > "${T}/join-mode"
      before=$(snap)
      start_join "$G1" ""
      settle
      after=$(snap | grep -v "^fleet-join.result ")
      [[ "$after" == "$before" ]] || fail "a worker ($mode) changed state files:
$(diff <(echo "$before") <(echo "$after"))"
      rc=0
      join_finished || rc=$?
      [[ "$(snap)" == "$before" ]] || fail "collecting a worker ($mode) changed state files"
      if [[ "$mode" == admit-after* ]]; then
        (( rc == 0 )) || fail "the admitting worker was not collected as admitted"
      fi
    done
  ' _ "$G1" >/dev/null || fail "worker-writes-nothing (exit $?)"
  echo "ok: worker-writes-nothing"
}

for check in ${CHECKS}; do
  "check_${check//-/_}"
done

echo "PASS: fleet-join runs in one background worker whose result only the loop acts on"
