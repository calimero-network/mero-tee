#!/usr/bin/env bash
# The should-join poll reports the devices merod holds revoked per namespace
# (`revoked_devices`), so mdma can refuse proofs signed by them.
#
# Absent means "no report", an empty list means "nothing revoked": a namespace
# whose read fails must be omitted from the map, never sent as `[]`.
#
# Checks (each runs the whole rendered sidecar with only curl and meroctl
# stubbed, and reads the bodies it actually POSTs to should-join):
#   reports   the devices merod reports revoked, and the withdrawn slots, per held
#             namespace arrive as `revoked_devices`, sorted and deduplicated.
#   partial   a namespace whose read fails is omitted (never `[]`), the others
#             stay, malformed device ids are dropped, and the omission is logged.
#   cap       past REVOKED_DEVICES_MAX ids in a namespace (mdma's per-node budget): the
#             first that many sorted, logged.
#   missing   no held list, or a file that is not a valid map, omits the field.
#   budget    a pass that runs out of budget sends the namespaces it did read.
#   large     a map bigger than one argv string, with one namespace past 2048 ids, is sent
#             in slices of at most 2048 ids beside held_namespaces, every id is reached, and
#             the small namespaces arrive whole on the first poll.
#   restart   a map written by an earlier sidecar process is never sent.
#
# FLEET_SIDECAR_TEMPLATE runs the checks against another template (a negative
# control against an older build); FLEET_SIDECAR_CHECKS picks which to run.
#
# Usage: scripts/ci/tests/fleet-sidecar-revoked-devices-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${FLEET_SIDECAR_TEMPLATE:-${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2}"
CHECKS="${FLEET_SIDECAR_CHECKS:-reports partial cap missing budget large restart}"

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
sed -e 's/^REVOKED_DEVICES_MAX=.*/REVOKED_DEVICES_MAX=5/' "${SB}/rendered.sh" > "${SB}/sidecar-cap.sh"
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
# with no assignments; revoked-devices answers from ${SB}/rev-<ns> (after
# ${SB}/rev-delay seconds) and fails when there is no such file.
cat > "${SB}/bin/curl" <<'STUB'
#!/usr/bin/env bash
body="" next=""
for a in "$@"; do
  if [[ "${next}" == "d" ]]; then body="${a}"; [[ "${body}" != "@-" ]] || body=$(cat); next=""; continue; fi
  [[ "${a}" == "-d" ]] && next="d"
done
for a in "$@"; do
  if [[ "${a}" == https://mdma.test/api/fleet/should-join ]]; then
    date +%s.%N >> "${SB}/polls"
    printf '%s\n' "${body}" >> "${SB}/bodies"
    echo '{"assignments":[]}'
    exit 0
  fi
  if [[ "${a}" == http://127.0.0.1:*/admin-api/namespaces/*/revoked-devices ]]; then
    ns="${a#*/namespaces/}"; ns="${ns%/revoked-devices}"
    sleep "$(cat "${SB}/rev-delay" 2>/dev/null || echo 0)"
    [[ -f "${SB}/rev-${ns}" ]] || exit 22
    cat "${SB}/rev-${ns}"
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
  rm -f "${SB}"/fleet-*.json "${SB}"/fleet-*.json.tmp "${SB}"/fleet-*.cursor "${SB}/ns-calls" "${SB}/polls" \
    "${SB}/bodies" "${SB}/ns-mode" "${SB}/ns-list" "${SB}/fleet-join.result" "${SB}"/rev-*
  : > "${SB}/fleet.log"
  : > "${SB}/polls"
  : > "${SB}/bodies"
  echo "test-token" > "${SB}/fleet-token"
  echo list > "${SB}/ns-mode"
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

# What each poll carried: one line per poll, "-" for no field, else the map.
rev_per_poll() {
  python3 -c '
import json, sys
for line in open(sys.argv[1]):
    if not line.strip():
        continue
    body = json.loads(line)
    print(json.dumps(body["revoked_devices"], sort_keys=True) if "revoked_devices" in body else "-")
' "${SB}/bodies"
}
rev_answer() { printf '{"revokedDevices": %s, "withdrawnSlots": %s}\n' "$2" "${3:-[]}" > "${SB}/rev-$1"; }
last_rev() { rev_per_poll | tail -1; }
count_lines() { if [[ -f "$1" ]]; then grep -c . "$1" || true; else echo 0; fi; }

sorted_map() { python3 -c 'import json,sys; print(json.dumps(json.loads(sys.argv[1]), sort_keys=True))' "$1"; }
dev() { printf '%064x' "$1"; }

# --- reports -----------------------------------------------------------------
check_reports() {
  reset_state
  local n1 n2 d1 d2 s1
  n1=$(ns 1); n2=$(ns 2); d1=$(dev 11); d2=$(dev 12); s1=$(dev 13)
  ns_list "$n1" "$n2" > "${SB}/ns-list"
  rev_answer "$n1" "[\"$d2\", \"$d1\", \"$d2\"]" "[\"$s1\"]"
  rev_answer "$n2" '[]'
  run_sidecar sidecar-60.sh 6
  local want
  want=$(sorted_map "{\"$n1\": [\"$d1\", \"$d2\", \"$s1\"], \"$n2\": []}")
  [[ "$(last_rev)" == "$want" ]] || fail "last poll carried $(last_rev), want ${want}"
  echo "ok: reports"
}

# --- partial -----------------------------------------------------------------
check_partial() {
  reset_state
  local n1 n2 d1
  n1=$(ns 1); n2=$(ns 2); d1=$(dev 11)
  ns_list "$n1" "$n2" > "${SB}/ns-list"
  rev_answer "$n1" "[\"$d1\", \"${d1:0:63}\", \"${d1}0\", \"$(tr 0-9 A-J <<<"$d1")\", 7, null]"
  run_sidecar sidecar-60.sh 6
  local want
  want=$(sorted_map "{\"$n1\": [\"$d1\"]}")
  [[ "$(last_rev)" == "$want" ]] || fail "unreadable namespace not omitted / bad ids not dropped: $(last_rev)"
  grep -q "revoked devices of 1 namespaces not read, omitted from revoked_devices: ${n2}" "${SB}/fleet.log" || fail "the omission is not logged"
  echo "ok: partial"
}

# --- cap ---------------------------------------------------------------------
check_cap() {
  reset_state
  local n1
  n1=$(ns 1)
  ns_list "$n1" > "${SB}/ns-list"
  python3 -c 'import json; print(json.dumps({"revokedDevices": [f"{i:064x}" for i in range(8)]}))' > "${SB}/rev-${n1}"
  run_sidecar sidecar-cap.sh 6
  python3 -c '
import json, sys
got = json.loads(sys.argv[2])[sys.argv[1]]
if got != [f"{i:064x}" for i in range(5)]:
    sys.exit(f"got {len(got)} ids")
' "$n1" "$(last_rev)" || fail "8 ids are not cut to the first 5 sorted"
  grep -q "has 8 revoked devices; revoked_devices reports the first 5" "${SB}/fleet.log" || fail "the cut is not logged"
  echo "ok: cap"
}

# --- missing -----------------------------------------------------------------
check_missing() {
  reset_state
  echo fail > "${SB}/ns-mode"
  rev_answer "$(ns 1)" "[\"$(dev 11)\"]"
  run_sidecar sidecar-60.sh 4
  [[ "$(rev_per_poll | sort -u)" == "-" ]] || fail "no held list, yet revoked_devices was sent"
  local bad
  for bad in 'not json' '[]' '{"x": []}' "{\"$(ns 1)\": \"nope\"}" "{\"$(ns 1)\": [\"zz\"]}"; do
    reset_state
    ns_list "$(ns 1)" > "${SB}/ns-list"
    rev_answer "$(ns 1)" "[\"$(dev 11)\"]"
    # shellcheck disable=SC2016  # evaluated by run_sidecar
    run_sidecar sidecar-60.sh 8 'for _ in $(seq 50); do grep -q revoked_devices "${SB}/bodies" && break; sleep 0.2; done; printf "%s\n" "$bad" > "${SB}/fleet-revoked-devices.json"' 1
    rev_per_poll | grep -q "$(ns 1)" || fail "no poll carried the map before '${bad}' replaced it"
    [[ "$(last_rev)" == "-" ]] || fail "invalid file '${bad}' was sent: $(last_rev)"
  done
  echo "ok: missing"
}

# --- budget ------------------------------------------------------------------
check_budget() {
  reset_state
  local n1 n2 n3 d1
  n1=$(ns 1); n2=$(ns 2); n3=$(ns 3); d1=$(dev 11)
  ns_list "$n1" "$n2" "$n3" > "${SB}/ns-list"
  rev_answer "$n1" "[\"$d1\"]"
  rev_answer "$n2" "[\"$d1\"]"
  rev_answer "$n3" "[\"$d1\"]"
  echo 3 > "${SB}/rev-delay"
  run_sidecar sidecar-60.sh 12
  python3 -c '
import json, sys
got = json.loads(sys.argv[1])
if len(got) != 1 or list(got.values()) != [[sys.argv[2]]]:
    sys.exit(f"got {got}")
' "$(last_rev)" "$d1" || fail "a pass cut by the budget did not send what it read: $(last_rev)"
  grep -q "ran out of budget" "${SB}/fleet.log" || fail "the cut pass is not logged"
  echo "ok: budget"
}

# --- large -------------------------------------------------------------------
check_large() {
  reset_state
  local n i
  for i in 1 2 3; do
    n=$(ns "$i")
    python3 -c 'import json, sys; print(json.dumps({"revokedDevices": [f"{i:064x}" for i in range(int(sys.argv[1]))]}))' \
      "$(( i == 1 ? 5000 : 10 ))" > "${SB}/rev-${n}"
  done
  ns_list "$(ns 1)" "$(ns 2)" "$(ns 3)" > "${SB}/ns-list"
  run_sidecar sidecar-60.sh 10
  python3 -c '
import json, sys
seen, first = set(), None
for line in open(sys.argv[1]):
    if not line.strip():
        continue
    body = json.loads(line)
    if "revoked_devices" not in body:
        continue
    if sum(map(len, body["revoked_devices"].values())) > 2048 or len(body.get("held_namespaces", [])) != 3:
        sys.exit("a poll carried more than 2048 ids or lost held_namespaces")
    first = first or body["revoked_devices"]
    seen |= {(ns, d) for ns, ids in body["revoked_devices"].items() for d in ids}
if sorted(len(first.get(f"{i:064x}", [])) for i in (2, 3)) != [10, 10]:
    sys.exit("the small namespaces waited behind the large one")
if len(seen) != 5020:
    sys.exit(f"only {len(seen)} of 5020 ids were ever sent")
' "${SB}/bodies" || fail "a 5020-id map was not sent in bounded slices reaching every id"
  echo "ok: large"
}

# --- restart -----------------------------------------------------------------
check_restart() {
  reset_state
  echo fail > "${SB}/ns-mode"
  printf '{"%s": []}\n' "$(ns 5)" > "${SB}/fleet-revoked-devices.json"
  run_sidecar sidecar-60.sh 4
  (( $(count_lines "${SB}/polls") >= 2 )) || fail "no polls"
  [[ "$(rev_per_poll | sort -u)" == "-" ]] || fail "a map left by an earlier process was sent"
  echo "ok: restart"
}

for check in ${CHECKS}; do
  "check_${check//-/_}"
done

echo "PASS: should-join reports revoked devices per namespace, and omits namespaces it could not read"
