#!/usr/bin/env bash
# The sidecar's python helpers take their inputs as argv, and poll_mdma checks
# the shape of every assignment before the loop acts on it.
#
# Values spliced into a `python3 -c "..."` body are re-parsed as Python, so any
# value with a quote in it breaks the helper, and the helpers' `|| echo` fallbacks
# then silently keep the old state. Passing values as argv keeps them data.
#
# Checks:
#   1. no double-quoted `python3 -c` body in the template expands a shell value;
#   2. poll_mdma accepts 32-byte hex group ids and fails the poll on anything
#      else (the safety gate then skips reconcile rather than leaving);
#   3. the state helpers round-trip a value containing quotes verbatim.
#
# Usage: scripts/ci/tests/fleet-sidecar-json-args-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
export SB

fail() { echo "FAIL: $*" >&2; exit 1; }

[[ -r "${TEMPLATE}" ]] || fail "cannot read ${TEMPLATE}"

# --- 1. static: no shell expansion inside a double-quoted python3 -c body ---
#
# Single-quoted bodies (`python3 -c '...'`) cannot expand anything, so only the
# double-quoted form is scanned. An escaped `\$` is a literal dollar and allowed.
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
# Quotes of both kinds and a backslash: everything a hand-built literal or
# body would have to escape.
ODD="it's-a-\"quoted\"-\\value'''"

assignments() {
  python3 -c 'import json,sys
print(json.dumps({"assignments": [{"group_id": int(g) if g.isdigit() else g} for g in sys.argv[1:]]}))' "$@"
}

# --- 2. poll_mdma checks the shape of every group id -----------------------
assignments "${GOOD}" > "${SB}/should-join"
poll_mdma peer1 mrtd1 > /dev/null || fail "a well-formed assignment was refused"
# mdma decodes ids with `bytes.fromhex`, so an uppercase id is one it can issue.
assignments "${GOOD^^}" > "${SB}/should-join"
poll_mdma peer1 mrtd1 > /dev/null || fail "an uppercase-hex assignment was refused"

for bad in "${ODD}" "${GOOD:0:62}" "${GOOD}0" "${GOOD:0:63}g" 42; do
  assignments "${GOOD}" "${bad}" > "${SB}/should-join"
  if poll_mdma peer1 mrtd1 > /dev/null; then
    fail "poll_mdma accepted group_id ${bad}; it must fail the whole poll"
  fi
done
echo '{"assignments":[{"no_group_id":true}]}' > "${SB}/should-join"
poll_mdma peer1 mrtd1 > /dev/null && fail "poll_mdma accepted an assignment with no group_id"

# --- 3. values round-trip through the helpers verbatim ---------------------
note_admitted "${ODD}"
python3 -c 'import json,sys; sys.exit(0 if sys.argv[1] in json.load(open(sys.argv[2])) else 1)' \
  "${ODD}" "${SB}/fleet-admitted.json" \
  || fail "note_admitted did not record the value verbatim: $(cat "${SB}/fleet-admitted.json")"

confirm_assignment peer1 "${ODD}" true RelayTee
python3 -c 'import json,sys
b = json.loads(open(sys.argv[1]).read().splitlines()[-1])
sys.exit(0 if b == {"peer_id": "peer1", "group_id": sys.argv[2], "authorship_ready": True, "tee_role": "RelayTee"} else 1)' \
  "${SB}/post-log" "${ODD}" \
  || fail "confirm_assignment did not send a well-formed body: $(tail -1 "${SB}/post-log")"

# Recorded as a relay while no role can be read (no executor account is known
# here), so the reconcile sees a change, reports it, and rewrites the entry.
python3 -c 'import json,sys; print(json.dumps({sys.argv[1]: "RelayTee"}))' "${ODD}" > "${SB}/fleet-authorship.json"
reconcile_authorship peer1 "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1:]))' "${ODD}")"
python3 -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[2])) == {sys.argv[1]: None} else 1)' \
  "${ODD}" "${SB}/fleet-authorship.json" \
  || fail "reconcile_authorship did not update the entry: $(cat "${SB}/fleet-authorship.json")"

echo "PASS: python helpers take argv and group ids are shape-checked"
