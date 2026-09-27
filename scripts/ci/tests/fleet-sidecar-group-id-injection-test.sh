#!/usr/bin/env bash
# The fleet sidecar must never let a value it did not write become code.
#
# The sidecar runs as root inside the TD and shells out to `python3 -c` for its
# JSON handling. It used to splice values straight into that Python source --
# `'$group_id'` inside a string literal, whole JSON sets inside `'''$desired'''`.
# `group_id` comes from mdma's `/api/fleet/should-join`, so a single quote in
# one id closed the literal and ran the rest as root in the TD, where merod's
# store key, group keys and the unlocked data-disk key all live. mdma is trusted
# to cause joins and leaves, not to execute code on the node.
#
# Two layers, both checked here:
#   1. `poll_mdma` refuses a response whose ids are not 32-byte hex,
#      failing the whole poll (the existing safety gate then skips reconcile)
#      rather than dropping the bad entry and reading it as "leave this".
#   2. No `python3 -c "..."` body expands a shell value; data is passed as
#      argv, so even an id that got past (1) stays data.
#
# Usage: scripts/ci/tests/fleet-sidecar-group-id-injection-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
export SB

fail() { echo "FAIL: $*" >&2; exit 1; }

[[ -r "${TEMPLATE}" ]] || fail "cannot read ${TEMPLATE}"

# --- 2. static: no shell expansion inside a double-quoted python3 -c body ---
#
# Single-quoted bodies (`python3 -c '...'`) cannot expand anything, so only the
# double-quoted form is scanned. `\$` would be a literal dollar, so it is
# allowed; nothing in the template needs one today.
if spliced="$(python3 - "${TEMPLATE}" <<'PY'
import re, sys
src = open(sys.argv[1]).read()
bad = []
for m in re.finditer(r'python3 -c "', src):
    j = m.end()
    while True:
        j = src.index('"', j)
        if src[j - 1] != '\\':
            break
        j += 1
    body = src[m.end():j]
    line = src.count('\n', 0, m.start()) + 1
    for k, text in enumerate(body.split('\n')):
        if re.search(r'(?<!\\)[$`]', text):
            bad.append(f"{line + k}: {text.strip()}")
print('\n'.join(bad))
sys.exit(1 if bad else 0)
PY
)"; then
  :
else
  echo "${spliced}" >&2
  fail "a python3 -c body expands a shell value; pass it as argv instead"
fi

# --- render the function half (same harness as the authorship test) --------
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

# --- stubs -----------------------------------------------------------------
mkdir -p "${SB}/bin"

# `curl`: answers should-join with ${SB}/should-join, logs every other POST
# body to ${SB}/post-log.
cat > "${SB}/bin/curl" <<'STUB'
#!/usr/bin/env bash
body="" url="" prev=""
for a in "$@"; do
  [[ "${prev}" == "-d" ]] && body="${a}"
  [[ "${a}" == http* ]] && url="${a}"
  prev="${a}"
done
if [[ "${url}" == */api/fleet/should-join ]]; then
  cat "${SB}/should-join"
  exit 0
fi
printf '%s\n' "${body}" >> "${SB}/post-log"
echo '{"status":"confirmed"}'
STUB
cat > "${SB}/bin/meroctl" <<'STUB'
#!/usr/bin/env bash
echo '{"data":{"capabilities":0}}'
STUB
chmod +x "${SB}/bin/curl" "${SB}/bin/meroctl"
PATH="${SB}/bin:${PATH}"
export PATH

# shellcheck source=/dev/null
source "${SB}/functions.sh"
: > "${SB}/post-log"

GOOD="$(printf 'ab%.0s' {1..32})"
MARKER="${SB}/pwned"
# Closes the single-quoted literal the old code wrapped the id in, then runs
# code that creates ${MARKER}. No whitespace (the space is rebuilt with chr),
# so it survives the word-split of `for group_id in $(...)` as a real one would.
EVIL="x'+__import__('os').system('touch'+chr(32)+'${MARKER}')+'"

json_list() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "$@"; }

# --- 1. poll_mdma refuses malformed ids, failing the whole poll -------------
python3 -c 'import json,sys; print(json.dumps({"assignments":[{"group_id":sys.argv[1]}]}))' \
  "${GOOD}" > "${SB}/should-join"
poll_mdma peer1 mrtd1 > /dev/null || fail "a well-formed assignment was refused"
# mdma decodes ids with `bytes.fromhex`, so an uppercase id is one it can issue.
python3 -c 'import json,sys; print(json.dumps({"assignments":[{"group_id":sys.argv[1]}]}))' \
  "${GOOD^^}" > "${SB}/should-join"
poll_mdma peer1 mrtd1 > /dev/null || fail "an uppercase-hex assignment was refused"

for bad in "${EVIL}" "${GOOD:0:62}" "${GOOD}0" "${GOOD:0:63}g" 42; do
  python3 -c 'import json,sys
v = sys.argv[1]
print(json.dumps({"assignments":[{"group_id":sys.argv[2]}, {"group_id": int(v) if v.isdigit() else v}]}))' \
    "${bad}" "${GOOD}" > "${SB}/should-join"
  if poll_mdma peer1 mrtd1 > /dev/null; then
    fail "poll_mdma accepted malformed group_id ${bad}; it must fail the whole poll"
  fi
done
echo '{"assignments":[{"no_group_id":true}]}' > "${SB}/should-join"
poll_mdma peer1 mrtd1 > /dev/null && fail "poll_mdma accepted an assignment with no group_id"

# --- 2. behavioural: an id that reaches the helpers stays data -------------
note_admitted "${EVIL}"
[[ -e "${MARKER}" ]] && fail "note_admitted executed the group id"
python3 -c 'import json,sys; sys.exit(0 if sys.argv[1] in json.load(open(sys.argv[2])) else 1)' \
  "${EVIL}" "${SB}/fleet-admitted.json" \
  || fail "note_admitted did not record the id verbatim"

confirm_assignment peer1 "${EVIL}" true
[[ -e "${MARKER}" ]] && fail "confirm_assignment executed the group id"
python3 -c 'import json,sys
b = json.loads(open(sys.argv[1]).read().splitlines()[-1])
sys.exit(0 if b == {"peer_id": "peer1", "group_id": sys.argv[2], "authorship_ready": True} else 1)' \
  "${SB}/post-log" "${EVIL}" \
  || fail "confirm_assignment did not send a well-formed body: $(tail -1 "${SB}/post-log")"

# Recorded as granted so the reconcile sees a change and takes the write path.
python3 -c 'import json,sys; print(json.dumps({sys.argv[1]: True}))' "${EVIL}" > "${SB}/fleet-authorship.json"
reconcile_authorship peer1 "$(json_list "${EVIL}")"
[[ -e "${MARKER}" ]] && fail "reconcile_authorship executed the group id"

echo "PASS: mdma-supplied group ids are validated and never executed"
