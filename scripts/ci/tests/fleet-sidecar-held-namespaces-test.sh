#!/usr/bin/env bash
# The should-join poll reports which namespaces merod holds (`held_namespaces`),
# so mdma can confirm a node it adopted for a namespace really holds it.
#
# Two meanings ride on one field and must never be confused: a list (even `[]`)
# says "this node holds exactly these", and NO field says "no report this
# cycle". A failed, hung or unreadable `meroctl namespace ls` must therefore
# drop the field, not send `[]` and not keep sending an older list.
#
# Checks (each runs the whole rendered sidecar with only curl and meroctl
# stubbed, and reads the bodies it actually POSTs to should-join):
#   reports     the stub's namespaces arrive lowercased, deduplicated and
#               sorted; polls before the first refresh lands omit the field.
#   empty       a node holding nothing reports `[]`, not an omitted field.
#   failure     a failing `namespace ls` omits the field; a list reported
#               before the failure is not sent after it.
#   timeout     a `namespace ls` that never returns is killed at its budget,
#               the field is omitted, and the poll keeps its 1s cadence.
#   cadence     with the image's interval, one `namespace ls` serves every poll
#               of the run (the last good list goes out with each); with a short
#               interval, refreshes follow it and never run per poll.
#   truncate    more than 512 namespaces: the first 512 in sorted order are
#               reported, and the cut is logged.
#   malformed   rows without a 64-hex `namespaceId` are dropped and logged; a
#               read in which no row has one, unparseable JSON, and a full
#               (possibly cut) page of 100 rows are no report at all.
#   restart     a list written by an earlier sidecar process is never sent.
#
# FLEET_SIDECAR_TEMPLATE runs the checks against another template (a negative
# control against an older build); FLEET_SIDECAR_CHECKS picks which to run.
#
# Usage: scripts/ci/tests/fleet-sidecar-held-namespaces-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${FLEET_SIDECAR_TEMPLATE:-${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2}"
CHECKS="${FLEET_SIDECAR_CHECKS:-reports empty failure timeout cadence truncate malformed restart}"

SB="$(mktemp -d)"
# Kill a process and everything under it.
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
    -e 's/^MEROCTL_KILL_GRACE=.*/MEROCTL_KILL_GRACE=1/' \
    -e 's/^MEROCTL_READ_TIMEOUT=.*/MEROCTL_READ_TIMEOUT=2/' \
    "${TEMPLATE}" > "${SB}/rendered.sh"
if grep -q '{{\|{%' "${SB}/rendered.sh"; then
  grep -n '{{\|{%' "${SB}/rendered.sh" >&2
  fail "unsubstituted template placeholders remain"
fi
grep -q '^HELD_NAMESPACES_INTERVAL=60$' "${SB}/rendered.sh" \
  || fail "the template does not refresh held namespaces every 60s (HELD_NAMESPACES_INTERVAL)"
# The image's interval, and a short one so a run sees several refreshes.
cp "${SB}/rendered.sh" "${SB}/sidecar-60.sh"
sed -e 's/^HELD_NAMESPACES_INTERVAL=.*/HELD_NAMESPACES_INTERVAL=3/' "${SB}/rendered.sh" > "${SB}/sidecar-3.sh"
printf '[identity]\npeer_id = "12D3KooWHeldTest"\n' > "${SB}/calimero/default/config.toml"

PATH="${SB}/bin:${PATH}"
export PATH

# `namespace ls` answers from ${SB}/ns-mode: "list" prints ${SB}/ns-list,
# "fail" exits 1, "hang" never returns. Every call is timestamped.
cat > "${SB}/bin/meroctl" <<'STUB'
#!/usr/bin/env bash
args=" $* "
if [[ "${args}" == *" peers "* ]]; then echo '{}'; exit 0; fi
if [[ "${args}" == *" namespace ls "* ]]; then
  date +%s.%N >> "${SB}/ns-calls"
  case "$(cat "${SB}/ns-mode" 2>/dev/null)" in
    list) cat "${SB}/ns-list"; exit 0 ;;
    hang) echo "$$" >> "${SB}/hung-pids"; exec sleep 300 ;;
    *) echo "error: connection refused" >&2; exit 1 ;;
  esac
fi
exit 1
STUB
# should-join records the time and the exact body of every poll and answers
# with no assignments; every other request fails.
cat > "${SB}/bin/curl" <<'STUB'
#!/usr/bin/env bash
body="" next=""
for a in "$@"; do
  if [[ "${next}" == "d" ]]; then body="${a}"; next=""; continue; fi
  [[ "${a}" == "-d" ]] && next="d"
done
for a in "$@"; do
  if [[ "${a}" == https://mdma.test/api/fleet/should-join ]]; then
    date +%s.%N >> "${SB}/polls"
    printf '%s\n' "${body}" >> "${SB}/bodies"
    echo '{"assignments":[]}'
    exit 0
  fi
done
exit 22
STUB
chmod +x "${SB}/bin/meroctl" "${SB}/bin/curl"

ns() { printf '%064x\n' "$1"; }
# A `namespace ls` answer naming the given ids.
ns_list() {
  python3 -c 'import json,sys; print(json.dumps({"data": [{"namespaceId": n, "memberCount": 1} for n in sys.argv[1:]]}))' "$@"
}

reset_state() {
  rm -f "${SB}"/fleet-*.json "${SB}"/fleet-*.json.tmp "${SB}/ns-calls" "${SB}/polls" \
    "${SB}/bodies" "${SB}/ns-mode" "${SB}/ns-list" "${SB}/fleet-join.result"
  : > "${SB}/fleet.log"
  : > "${SB}/polls"
  : > "${SB}/bodies"
  echo "test-token" > "${SB}/fleet-token"
}

# Runs a sidecar script for $2 seconds; $3, if given, is run after $4 seconds
# (a mid-run change to the stub).
run_sidecar() {
  local script="$1" run="$2" midway="${3:-}" at="${4:-0}" t=0
  bash "${SB}/${script}" >/dev/null 2>&1 &
  local pid=$!
  while (( t < run )); do
    if [[ -n "$midway" ]] && (( t == at )); then eval "$midway"; fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 1
    t=$(( t + 1 ))
  done
  kill -0 "$pid" 2>/dev/null || fail "the sidecar exited after ${t}s: $(tail -3 "${SB}/fleet.log")"
  kill_tree "$pid"
  wait "$pid" 2>/dev/null || true
}

# What each poll carried: one line per poll, "-" for no field, else the list.
held_per_poll() {
  python3 -c '
import json, sys
for line in open(sys.argv[1]):
    if not line.strip():
        continue
    body = json.loads(line)
    print(json.dumps(body["held_namespaces"]) if "held_namespaces" in body else "-")
' "${SB}/bodies"
}
count_lines() { if [[ -f "$1" ]]; then grep -c . "$1" || true; else echo 0; fi; }
max_poll_gap() {
  python3 -c '
import sys
ts = [float(l) for l in open(sys.argv[1]) if l.strip()]
gaps = [b - a for a, b in zip(ts, ts[1:])]
print(round(max(gaps), 2) if gaps else 99)
' "${SB}/polls"
}
lt() { python3 -c 'import sys; sys.exit(0 if float(sys.argv[1]) < float(sys.argv[2]) else 1)' "$1" "$2"; }

# --- reports -----------------------------------------------------------------
check_reports() {
  reset_state
  local a b c
  a=$(ns 3); b=$(ns 1); c="ABCDEF$(printf '0%.0s' {1..58})"
  echo list > "${SB}/ns-mode"
  ns_list "$a" "$b" "$c" "$a" "$(tr 'a-f' 'A-F' <<<"$b")" > "${SB}/ns-list"
  run_sidecar sidecar-60.sh 6
  local want
  want=$(python3 -c 'import json,sys; print(json.dumps(sorted({x.lower() for x in sys.argv[1:]})))' "$a" "$b" "$c")
  local polls
  polls=$(count_lines "${SB}/bodies")
  (( polls >= 3 )) || fail "only ${polls} polls in 6s"
  held_per_poll | grep -qxF "$want" \
    || fail "no poll carried the held namespaces ${want}; got: $(held_per_poll | sort -u | tr '\n' ' ')"
  held_per_poll | grep -vxF "$want" | grep -vx -- '-' \
    && fail "a poll carried something other than the held list or nothing"
  # Once reported, every later poll carries it.
  python3 -c '
import sys
rows = [l.strip() for l in open(sys.argv[1])]
first = next(i for i, r in enumerate(rows) if r != "-")
if any(r == "-" for r in rows[first:]):
    sys.exit("the field went missing after the list was read")
' <(held_per_poll) || fail "held_namespaces is not sent with every poll after the first refresh"
  echo "ok: reports (${polls} polls)"
}

# --- empty -------------------------------------------------------------------
check_empty() {
  reset_state
  echo list > "${SB}/ns-mode"
  echo '{"data": []}' > "${SB}/ns-list"
  run_sidecar sidecar-60.sh 5
  held_per_poll | grep -qx '\[\]' || fail "a node holding nothing must report [], got: $(held_per_poll | sort -u | tr '\n' ' ')"
  echo "ok: empty"
}

# --- failure -----------------------------------------------------------------
check_failure() {
  reset_state
  echo fail > "${SB}/ns-mode"
  run_sidecar sidecar-3.sh 6
  (( $(count_lines "${SB}/ns-calls") >= 2 )) || fail "a failing namespace ls was not retried"
  [[ "$(held_per_poll | sort -u)" == "-" ]] \
    || fail "a failing namespace ls must omit held_namespaces, got: $(held_per_poll | sort -u | tr '\n' ' ')"
  grep -q "meroctl namespace ls rc=1; not reporting held namespaces" "${SB}/fleet.log" \
    || fail "the failed read is not logged"
  # A good list, then failures: the list must stop being sent.
  reset_state
  echo list > "${SB}/ns-mode"
  ns_list "$(ns 7)" > "${SB}/ns-list"
  # shellcheck disable=SC2016  # evaluated by run_sidecar
  run_sidecar sidecar-3.sh 12 'echo fail > "${SB}/ns-mode"' 4
  local seq
  seq=$(held_per_poll | uniq | tr '\n' ' ')
  held_per_poll | grep -q "$(ns 7)" || fail "the list was never reported before the failure: ${seq}"
  [[ "$(held_per_poll | tail -1)" == "-" ]] \
    || fail "a list read before namespace ls started failing is still sent: ${seq}"
  echo "ok: failure (${seq})"
}

# --- timeout -----------------------------------------------------------------
check_timeout() {
  reset_state
  echo hang > "${SB}/ns-mode"
  run_sidecar sidecar-3.sh 12
  local calls gap polls
  calls=$(count_lines "${SB}/ns-calls")
  polls=$(count_lines "${SB}/polls")
  gap=$(max_poll_gap)
  echo "   namespace ls hanging: ${polls} polls, ${calls} reads, longest gap ${gap}s"
  (( calls >= 2 )) || fail "a hung namespace ls was not killed and retried (${calls} reads)"
  (( polls >= 6 )) || fail "only ${polls} polls in 12s while namespace ls hangs"
  lt "$gap" 2.5 || fail "the poll stalled ${gap}s behind a hung namespace ls"
  [[ "$(held_per_poll | sort -u)" == "-" ]] \
    || fail "a hung namespace ls must omit held_namespaces, got: $(held_per_poll | sort -u | tr '\n' ' ')"
  grep -q "meroctl namespace ls timed out after 2s" "${SB}/fleet.log" || fail "the hung read is not logged as timed out"
  echo "ok: timeout"
}

# --- cadence -----------------------------------------------------------------
check_cadence() {
  reset_state
  echo list > "${SB}/ns-mode"
  ns_list "$(ns 9)" > "${SB}/ns-list"
  run_sidecar sidecar-60.sh 9
  local calls polls carried
  calls=$(count_lines "${SB}/ns-calls")
  polls=$(count_lines "${SB}/polls")
  carried=$(held_per_poll | grep -c "$(ns 9)" || true)
  (( calls == 1 )) || fail "with a 60s interval, ${calls} namespace ls in 9s (want 1)"
  (( polls >= 5 && carried >= polls - 2 )) \
    || fail "the last good list is not sent with each poll (${carried} of ${polls} polls carried it)"
  reset_state
  echo list > "${SB}/ns-mode"
  ns_list "$(ns 9)" > "${SB}/ns-list"
  run_sidecar sidecar-3.sh 10
  calls=$(count_lines "${SB}/ns-calls")
  polls=$(count_lines "${SB}/polls")
  (( calls >= 2 && calls <= 4 )) || fail "with a 3s interval, ${calls} namespace ls in 10s (want 2-4)"
  (( polls > calls + 2 )) || fail "namespace ls ran about once per poll (${calls} reads, ${polls} polls)"
  python3 -c '
import sys
ts = [float(l) for l in open(sys.argv[1]) if l.strip()]
gaps = [b - a for a, b in zip(ts, ts[1:])]
if gaps and min(gaps) < 2.5:
    sys.exit(f"two refreshes {min(gaps):.2f}s apart under a 3s interval")
' "${SB}/ns-calls" || fail "refreshes ran faster than the interval"
  echo "ok: cadence"
}

# --- truncate ----------------------------------------------------------------
check_truncate() {
  reset_state
  echo list > "${SB}/ns-mode"
  python3 -c '
import json, random
ids = [f"{i:064x}" for i in range(600)]
random.shuffle(ids)
print(json.dumps({"data": [{"namespaceId": n} for n in ids]}))' > "${SB}/ns-list"
  run_sidecar sidecar-60.sh 5
  python3 -c '
import json, sys
lists = [json.loads(l) for l in open(sys.argv[1]) if l.strip() != "-"]
if not lists:
    sys.exit("no poll carried held_namespaces")
want = [f"{i:064x}" for i in range(512)]
for got in lists:
    if got != want:
        sys.exit(f"want the first 512 sorted ids, got {len(got)} starting {got[:1]}")
' <(held_per_poll) || fail "600 namespaces are not cut to the first 512 sorted"
  grep -q "this node holds 600 namespaces; held_namespaces reports the first 512" "${SB}/fleet.log" \
    || fail "the cut is not logged"
  echo "ok: truncate"
}

# --- malformed ---------------------------------------------------------------
check_malformed() {
  reset_state
  echo list > "${SB}/ns-mode"
  local good1 good2
  good1=$(ns 4); good2=$(ns 2)
  python3 -c '
import json, sys
g1, g2 = sys.argv[1], sys.argv[2]
rows = [
    {"namespaceId": g1},
    {"namespaceId": g1[:63]},
    {"namespaceId": g1 + "0"},
    {"namespaceId": "z" * 64},
    {"namespaceId": " " + g2},
    {"namespaceId": 12},
    {"name": "no id"},
    "a string row",
    None,
    {"namespaceId": g2},
]
print(json.dumps({"data": rows}))' "$good1" "$good2" > "${SB}/ns-list"
  run_sidecar sidecar-60.sh 5
  local want
  want=$(python3 -c 'import json,sys; print(json.dumps(sorted(sys.argv[1:])))' "$good1" "$good2")
  [[ "$(held_per_poll | grep -vx -- '-' | sort -u)" == "$want" ]] \
    || fail "malformed ids are not filtered: $(held_per_poll | sort -u | tr '\n' ' ')"
  grep -q "dropped 8 namespace row(s) with no 64-hex namespaceId" "${SB}/fleet.log" \
    || fail "dropped rows are not logged"

  # Rows but no usable id at all, unparseable JSON, a body with no data array,
  # and a full page: nothing trustworthy, so no report -- never `[]`.
  local body
  for body in '{"data": [{"id": "x"}, {"namespaceId": "nothex"}]}' '{"data": [' '{"items": []}' FULLPAGE; do
    reset_state
    echo list > "${SB}/ns-mode"
    if [[ "$body" == FULLPAGE ]]; then
      python3 -c 'import json; print(json.dumps({"data": [{"namespaceId": f"{i:064x}"} for i in range(100)]}))' > "${SB}/ns-list"
    else
      printf '%s\n' "$body" > "${SB}/ns-list"
    fi
    run_sidecar sidecar-60.sh 4
    (( $(count_lines "${SB}/polls") >= 2 )) || fail "no polls with namespace ls answering ${body:0:30}"
    [[ "$(held_per_poll | sort -u)" == "-" ]] \
      || fail "namespace ls answering '${body:0:30}' must omit held_namespaces, got: $(held_per_poll | sort -u | cut -c1-80 | tr '\n' ' ')"
  done
  echo "ok: malformed"
}

# --- restart -----------------------------------------------------------------
check_restart() {
  reset_state
  echo fail > "${SB}/ns-mode"
  printf '["%s"]\n' "$(ns 5)" > "${SB}/fleet-held-namespaces.json"
  run_sidecar sidecar-60.sh 4
  (( $(count_lines "${SB}/polls") >= 2 )) || fail "no polls"
  [[ "$(held_per_poll | sort -u)" == "-" ]] \
    || fail "a list left by an earlier process was sent: $(held_per_poll | sort -u | tr '\n' ' ')"
  echo "ok: restart"
}

for check in ${CHECKS}; do
  "check_${check//-/_}"
done

echo "PASS: should-join reports the namespaces merod holds, and omits the field when it cannot tell"
