#!/usr/bin/env bash
# Behavioural test for the fleet sidecar's authorship-reporting logic.
#
# `reconcile_authorship` is the trickiest code in the sidecar and the only part
# with no other safety net: it decides when this node tells MDMA that it can
# serve delegated execution for a namespace. Getting it wrong is silent in both
# directions — report too eagerly and clients are sent to mint warrants the node
# would refuse; report too rarely and a namespace whose admin switched it to
# relay mode never becomes writable at all.
#
# The answer is the node's TEE role: only a `RelayTee` relays (core answers a
# `ReadOnlyTee` with a 403), while both roles are admitted TEE members and are
# reported as such in `tee_role`.
#
# It cannot be covered by the release probes: those need a live TDX node, an
# MDMA, and a namespace admin changing the TEE admission policy. So this renders the
# template, sources the function half, and drives it against stubbed `meroctl`
# and `curl`.
#
# Usage: scripts/ci/tests/fleet-sidecar-authorship-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
export SB

# --- render the template ---------------------------------------------------
# The two Jinja placeholders are substituted directly rather than through
# Ansible: this test is about the shell logic, and pulling in Jinja would make a
# shell test depend on a Python toolchain being present.
#
# The state directory is redirected wholesale rather than file by file. A
# per-file list silently misses any state file added to the sidecar later: the
# sourced template then tries to create it under the real /mnt/data/fleet,
# which does not exist on a CI runner, and the failure lands in THIS test rather
# than in the change that caused it.
if [[ ! -r "${TEMPLATE}" ]]; then
  echo "FAIL: cannot read ${TEMPLATE}" >&2
  exit 1
fi
# `@` as the delimiter throughout: the auth-token placeholder contains a Jinja
# filter pipe, which `s|…|…|` would read as the end of the pattern.
sed -e 's@{{ fleet_mdma_url }}@https://mdma.test@' \
    -e "s@{{ fleet_auth_token | default('') }}@@" \
    -e "s@/run/calimero/fleet-sidecar.log@${SB}/fleet.log@" \
    -e "s@/mnt/data/fleet/@${SB}/@g" \
    -e "s@/etc/vector@${SB}/vector@g" \
    -e "s@/etc/vmagent@${SB}/vmagent@g" \
    "${TEMPLATE}" > "${SB}/rendered.sh"

# Only the function half: the main loop polls forever.
if ! grep -q '^# --- Main loop ---$' "${SB}/rendered.sh"; then
  echo "FAIL: the sidecar template no longer has a '# --- Main loop ---' marker;" \
       "this test slices on it" >&2
  exit 1
fi
sed -n '1,/^# --- Main loop ---$/p' "${SB}/rendered.sh" | sed '$d' > "${SB}/functions.sh"

if grep -q '{{\|{%' "${SB}/functions.sh"; then
  echo "FAIL: unsubstituted Jinja left in the rendered sidecar:" >&2
  grep -n '{{\|{%' "${SB}/functions.sh" >&2
  exit 1
fi

# Every state file the rendered sidecar touches must land in the sandbox.
# Sourcing the template executes its top-level `[[ -f "$X" ]] || echo ... > "$X"`
# initialisers, so one path outside ${SB} either writes to the developer's real
# machine or -- on a CI runner, where /mnt/data/fleet does not exist -- fails
# the whole test with an error pointing at the harness rather than at the change
# that caused it. That is exactly how adding `INVENTORY_FILE` broke this test.
#
# The wholesale substitution above already covers anything under
# /mnt/data/fleet; this catches a state file introduced somewhere else.
if leaked="$(grep -nE '^[A-Za-z_]+_FILE="[^"]*"' "${SB}/functions.sh" | grep -v "${SB}/")"; then
  echo "FAIL: the rendered sidecar keeps state outside the sandbox:" >&2
  echo "${leaked}" >&2
  echo "       add it to the substitution above." >&2
  exit 1
fi

# --- stubs -----------------------------------------------------------------
mkdir -p "${SB}/bin" "${SB}/roles"

# `meroctl`: `account show` with a fixed account. Every call is logged to
# ${SB}/meroctl-log, so a test can assert that no capability read decides
# authorship any more.
cat > "${SB}/bin/meroctl" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SB}/meroctl-log"
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  if [[ "${args[i]}" == "get-capabilities" ]]; then
    echo '{"data":{"capabilities":512}}'
    exit 0
  fi
  if [[ "${args[i]}" == "account" && "${args[i + 1]:-}" == "show" ]]; then
    echo '{"data":{"accountId":"4D4D4D"}}'
    exit 0
  fi
done
exit 1
STUB

# `curl`, two roles:
#   * merod's `GET http://127.0.0.1:<port>/admin-api/groups/<ns>/members
#     ?offset=&limit=`: the namespace's members are this node (account 4d4d4d)
#     with the role in ${SB}/roles/<ns>, plus an admin; a missing file is an
#     HTTP error, and an empty one leaves this node out of the list.
#   * mdma: appends each POST body to ${SB}/confirm-log, or fails while
#     ${SB}/confirm-fails exists so the retry path can be driven.
cat > "${SB}/bin/curl" <<'STUB'
#!/usr/bin/env bash
body="" url="" prev=""
for a in "$@"; do
  [[ "${prev}" == "-d" ]] && body="${a}"
  [[ "${a}" == http* ]] && url="${a}"
  prev="${a}"
done
if [[ "${url}" == http://127.0.0.1:*/admin-api/groups/*/members\?* ]]; then
  exec python3 - "${url}" <<'PY'
import json, os, sys
from urllib.parse import parse_qs, urlparse
u = urlparse(sys.argv[1])
ns = u.path.split("/")[3]
q = parse_qs(u.query)
offset, limit = int(q["offset"][0]), int(q["limit"][0])
path = os.path.join(os.environ["SB"], "roles", ns)
if not os.path.exists(path):
    sys.exit(22)
role = open(path).read().strip()
rows = [{"identity": "00" * 32, "role": "Admin"}]
if role:
    rows.append({"identity": "4d4d4d", "role": role})
print(json.dumps({"members": rows[offset:offset + limit]}))
PY
fi
[[ -f "${SB}/confirm-fails" ]] && exit 22
printf '%s\n' "${body}" >> "${SB}/confirm-log"
echo '{"status":"confirmed"}'
STUB

chmod +x "${SB}/bin/meroctl" "${SB}/bin/curl"
PATH="${SB}/bin:${PATH}"
export PATH

# shellcheck source=/dev/null
source "${SB}/functions.sh"

# Read by `read_tee_role` in the sourced sidecar, which shellcheck cannot see
# across the `source` of a generated file.
# shellcheck disable=SC2034
EXECUTOR_ACCOUNT="4d4d4d"
: > "${SB}/confirm-log"
: > "${SB}/meroctl-log"

fail() { echo "FAIL: $*" >&2; exit 1; }
confirms() { awk 'NF{n++} END{print n+0}' "${SB}/confirm-log"; }
expect_confirms() {
  local want="$1" why="$2" got
  got="$(confirms)"
  [[ "${got}" == "${want}" ]] || fail "${why} (expected ${want} confirms, got ${got})"
}
role() { printf '%s\n' "$2" > "${SB}/roles/$1"; }
# The last confirm body's `authorship_ready` and `tee_role`, as JSON.
last_confirm() {
  tail -1 "${SB}/confirm-log" | python3 -c '
import json, sys
b = json.load(sys.stdin)
print(json.dumps(b["authorship_ready"]), json.dumps(b["tee_role"]))'
}
expect_last() {
  local want="$1" why="$2" got
  got="$(last_confirm)"
  [[ "${got}" == "${want}" ]] || fail "${why} (expected '${want}', got '${got}'): $(tail -1 "${SB}/confirm-log")"
}

# 1. A replica, and join-time already recorded that. Nothing to say.
#    The loop runs once a second and /confirm is a write, so "no change" has to
#    be silent or the sidecar writes to MDMA 86400 times a day per namespace.
role aa ReadOnlyTee
save_authorship '{"aa":"ReadOnlyTee"}'
reconcile_authorship peer1 '["aa"]'
expect_confirms 0 "an unchanged role must not be re-POSTed"

# 2. An admin switches the namespace to relay mode, converting this node to a
#    RelayTee. Exactly one POST: authorship ready, and the role that makes it so.
#    This is the case the whole function exists for: the conversion lands long
#    after admission, so a join-time answer alone would be frozen at false
#    forever and the cloud would never advertise this relay.
role aa RelayTee
reconcile_authorship peer1 '["aa"]'
expect_confirms 1 "a conversion to RelayTee must be reported"
expect_last 'true "RelayTee"' "a RelayTee is authorship-ready"
grep -q '"group_id":"aa"' "${SB}/confirm-log" \
  || fail "the confirm body must name the group"

# 3. Steady state stays silent.
reconcile_authorship peer1 '["aa"]'
reconcile_authorship peer1 '["aa"]'
expect_confirms 1 "steady state must not re-POST"

# 4. Back to replica mode: no longer ready, and still reported as an admitted
#    TEE member rather than as nothing. The capability read that used to decide
#    this must not come back: the stub grants CAN_AUTHOR_ON_BEHALF to anyone
#    asking, which core ignores for a ReadOnlyTee.
role aa ReadOnlyTee
reconcile_authorship peer1 '["aa"]'
expect_confirms 2 "a conversion back to ReadOnlyTee must be reported"
expect_last 'false "ReadOnlyTee"' "a ReadOnlyTee is a TEE member but not authorship-ready"
grep -q 'get-capabilities' "${SB}/meroctl-log" \
  && fail "authorship must come from the role, not a capability read: $(cat "${SB}/meroctl-log")"

# 5. A failed POST must not advance the recorded state, or the change is lost
#    forever — the next cycle would see "no change" and stay silent.
role aa RelayTee
touch "${SB}/confirm-fails"
reconcile_authorship peer1 '["aa"]'
rm -f "${SB}/confirm-fails"
grep -q '"aa": "ReadOnlyTee"' "${SB}/fleet-authorship.json" \
  || fail "a failed POST must leave the state unadvanced: $(cat "${SB}/fleet-authorship.json")"
reconcile_authorship peer1 '["aa"]'
expect_confirms 3 "the retry after a failed POST must happen"
expect_last 'true "RelayTee"' "the retry must carry the new role"

# 6. A namespace MDMA no longer assigns is pruned, so a later re-join is treated
#    as new rather than inheriting a stale "already reported" verdict.
reconcile_authorship peer1 '[]'
[[ "$(cat "${SB}/fleet-authorship.json")" == "{}" ]] \
  || fail "a dropped namespace must be pruned: $(cat "${SB}/fleet-authorship.json")"

# 7. An unreadable member list is not ready and no role, never a crash and never
#    true. This is the safe direction: MDMA does not advertise the node, so
#    clients are not sent to mint warrants it would refuse.
save_authorship '{"bb":"RelayTee"}'
reconcile_authorship peer1 '["bb"]'
expect_last 'false null' "an unreadable role must report not ready"

# 8. A record written by an older sidecar holds the boolean it derived from a
#    capability, which matches no role: it is re-reported once, so mdma learns
#    the role, and then goes quiet.
role cc RelayTee
save_authorship '{"cc":true}'
reconcile_authorship peer1 '["cc"]'
reconcile_authorship peer1 '["cc"]'
expect_confirms 5 "a legacy boolean record must be re-reported exactly once"
expect_last 'true "RelayTee"' "the re-report must carry the role"

# 9. Roles that are not TEE roles -- a plain member, or one a newer core adds --
#    are neither a relay nor reported as a TEE role, and parsing them must not
#    fail.
for other in ReadOnly Admin SomeFutureTee; do
  role dd "${other}"
  save_authorship '{"dd":"RelayTee"}'
  reconcile_authorship peer1 '["dd"]'
  expect_last 'false null' "role ${other} must not be authorship-ready"
done

# 10. The executor account is parsed out of meroctl's JSON and lower-cased — it
#     is what a warrant's `executor` must name, and what this node's own member
#     row is found by, so a mis-parse makes every write to this relay
#     unspendable.
account="$(get_executor_account)"
[[ "${account}" == "4d4d4d" ]] || fail "executor account parse returned '${account}'"

echo "OK: fleet sidecar authorship reporting — 10 checks, $(confirms) confirms posted"
