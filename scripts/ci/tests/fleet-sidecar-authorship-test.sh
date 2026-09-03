#!/usr/bin/env bash
# Behavioural test for the fleet sidecar's authorship-reporting logic.
#
# `reconcile_authorship` is the trickiest code in the sidecar and the only part
# with no other safety net: it decides when this node tells MDMA that it can
# serve delegated execution for a namespace. Getting it wrong is silent in both
# directions — report too eagerly and clients are sent to mint warrants the node
# would refuse; report too rarely and a namespace whose admin granted the
# capability never becomes writable at all.
#
# It cannot be covered by the release probes: those need a live TDX node, an
# MDMA, and a namespace admin publishing a governance op. So this renders the
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
if [[ ! -r "${TEMPLATE}" ]]; then
  echo "FAIL: cannot read ${TEMPLATE}" >&2
  exit 1
fi
# `@` as the delimiter throughout: the auth-token placeholder contains a Jinja
# filter pipe, which `s|…|…|` would read as the end of the pattern.
sed -e 's@{{ fleet_mdma_url }}@https://mdma.test@' \
    -e "s@{{ fleet_auth_token | default('') }}@@" \
    -e "s@/var/log/fleet-sidecar.log@${SB}/fleet.log@" \
    -e "s@/var/lib/calimero/fleet-confirmed.json@${SB}/confirmed.json@" \
    -e "s@/var/lib/calimero/fleet-authorship.json@${SB}/authorship.json@" \
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

# --- stubs -----------------------------------------------------------------
mkdir -p "${SB}/bin"

# `meroctl`: answers `group members get-capabilities` from ${SB}/caps
# ("<group>=<mask>" lines, default 0 — the closed-by-default state core has),
# and `account show` with a fixed account.
cat > "${SB}/bin/meroctl" <<'STUB'
#!/usr/bin/env bash
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  if [[ "${args[i]}" == "get-capabilities" ]]; then
    mask="$(grep -E "^${args[i + 1]}=" "${SB}/caps" 2>/dev/null | tail -1 | cut -d= -f2)"
    printf '{"data":{"capabilities":%s}}\n' "${mask:-0}"
    exit 0
  fi
  if [[ "${args[i]}" == "account" && "${args[i + 1]:-}" == "show" ]]; then
    echo '{"data":{"accountId":"4D4D4D"}}'
    exit 0
  fi
done
exit 1
STUB

# `curl`: appends each POST body to ${SB}/confirm-log, or fails while
# ${SB}/confirm-fails exists so the retry path can be driven.
cat > "${SB}/bin/curl" <<'STUB'
#!/usr/bin/env bash
body=""
prev=""
for a in "$@"; do
  [[ "${prev}" == "-d" ]] && body="${a}"
  prev="${a}"
done
[[ -f "${SB}/confirm-fails" ]] && exit 22
printf '%s\n' "${body}" >> "${SB}/confirm-log"
echo '{"status":"confirmed"}'
STUB

chmod +x "${SB}/bin/meroctl" "${SB}/bin/curl"
PATH="${SB}/bin:${PATH}"
export PATH

# shellcheck source=/dev/null
source "${SB}/functions.sh"

# Read by `check_authorship` in the sourced sidecar, which shellcheck cannot
# see across the `source` of a generated file.
# shellcheck disable=SC2034
EXECUTOR_ACCOUNT="4d4d4d"
: > "${SB}/caps"
: > "${SB}/confirm-log"

fail() { echo "FAIL: $*" >&2; exit 1; }
confirms() { awk 'NF{n++} END{print n+0}' "${SB}/confirm-log"; }
expect_confirms() {
  local want="$1" why="$2" got
  got="$(confirms)"
  [[ "${got}" == "${want}" ]] || fail "${why} (expected ${want} confirms, got ${got})"
}

# 1. No grant, and join-time already recorded that. Nothing to say.
#    The loop runs once a second and /confirm is a write, so "no change" has to
#    be silent or the sidecar writes to MDMA 86400 times a day per namespace.
save_authorship '{"aa":false}'
reconcile_authorship peer1 '["aa"]'
expect_confirms 0 "an unchanged answer must not be re-POSTed"

# 2. An admin grants the capability. Exactly one POST, carrying true.
#    This is the case the whole function exists for: the grant lands long after
#    admission, so a join-time answer alone would be frozen at false forever and
#    the cloud would never advertise this relay.
echo "aa=512" > "${SB}/caps"
reconcile_authorship peer1 '["aa"]'
expect_confirms 1 "a granted capability must be reported"
grep -q '"authorship_ready":true' "${SB}/confirm-log" \
  || fail "the confirm body must carry authorship_ready:true: $(cat "${SB}/confirm-log")"
grep -q '"group_id":"aa"' "${SB}/confirm-log" \
  || fail "the confirm body must name the group"

# 3. Steady state stays silent.
reconcile_authorship peer1 '["aa"]'
reconcile_authorship peer1 '["aa"]'
expect_confirms 1 "steady state must not re-POST"

# 4. Revocation travels back, so the cloud stops advertising the relay.
echo "aa=0" > "${SB}/caps"
reconcile_authorship peer1 '["aa"]'
expect_confirms 2 "a revoked capability must be reported"
tail -1 "${SB}/confirm-log" | grep -q '"authorship_ready":false' \
  || fail "a revocation must report false"

# 5. A failed POST must not advance the recorded state, or the change is lost
#    forever — the next cycle would see "no change" and stay silent.
echo "aa=512" > "${SB}/caps"
touch "${SB}/confirm-fails"
reconcile_authorship peer1 '["aa"]'
rm -f "${SB}/confirm-fails"
grep -q '"aa": false' "${SB}/authorship.json" \
  || fail "a failed POST must leave the state unadvanced: $(cat "${SB}/authorship.json")"
reconcile_authorship peer1 '["aa"]'
expect_confirms 3 "the retry after a failed POST must happen"

# 6. A namespace MDMA no longer assigns is pruned, so a later re-join is treated
#    as new rather than inheriting a stale "already reported" verdict.
reconcile_authorship peer1 '[]'
[[ "$(cat "${SB}/authorship.json")" == "{}" ]] \
  || fail "a dropped namespace must be pruned: $(cat "${SB}/authorship.json")"

# 7. An unreadable capability is false, never a crash and never true. This is
#    the safe direction: MDMA does not advertise the node, so clients are not
#    sent to mint warrants it would refuse.
mv "${SB}/bin/meroctl" "${SB}/bin/meroctl.off"
save_authorship '{"bb":true}'
reconcile_authorship peer1 '["bb"]'
mv "${SB}/bin/meroctl.off" "${SB}/bin/meroctl"
tail -1 "${SB}/confirm-log" | grep -q '"authorship_ready":false' \
  || fail "an unreadable capability must report false"

# 8. The executor account is parsed out of meroctl's JSON and lower-cased — it
#    is what a warrant's `executor` must name, so a mis-parse makes every write
#    to this relay unspendable.
account="$(get_executor_account)"
[[ "${account}" == "4d4d4d" ]] || fail "executor account parse returned '${account}'"

echo "OK: fleet sidecar authorship reporting — 8 checks, $(confirms) confirms posted"
