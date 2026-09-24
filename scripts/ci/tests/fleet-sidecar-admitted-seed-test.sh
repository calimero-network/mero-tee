#!/usr/bin/env bash
# The admitted set must survive the upgrade that introduced it.
#
# `admitted - desired` is what makes a fleet node self-leave a namespace whose
# HA was disabled. The set is written by `note_admitted`, which runs only inside
# the join loop -- and that loop SKIPS any namespace already in CONFIRMED_FILE
# ("membership is stable until mdma drops the assignment").
#
# So on the first boot after the build that added ADMITTED_FILE, a node has a
# populated confirmed set and an empty admitted one, and nothing will ever fill
# it for the namespaces it joined earlier. `admitted - desired` is empty for
# them forever, a later HA disable never makes the node leave, and it keeps the
# namespace's key as a `ReadOnlyTee` member of the owner's group -- which is
# calimero-network/mdma#155, reproduced on the installed base by the very fix
# that closed it for new admissions.
#
# `seed_admitted_from_confirmed` bridges that boot. The properties worth pinning
# are about DIRECTION and IDEMPOTENCE, because both failure modes are silent:
#
#   * seeding too WIDE would make a node leave, and irreversibly purge keys for,
#     a namespace it was never admitted to. confirmed is a subset of admitted by
#     construction, so seeding from it can only under-count;
#   * re-seeding on every boot would resurrect namespaces the node has since
#     legitimately left, making it try to leave them again forever;
#   * guarding on CONTENT rather than existence would re-seed a node whose
#     admitted set is legitimately empty, on every single boot.
#
# Behavioural, not a grep: this renders the template, sources the function half
# and drives the real function against a sandbox, the same shape as
# fleet-sidecar-recovery-test.sh.
#
# Usage: scripts/ci/tests/fleet-sidecar-admitted-seed-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT

if [[ ! -r "${TEMPLATE}" ]]; then
  echo "FAIL: cannot read ${TEMPLATE}" >&2
  exit 1
fi

fail() { echo "FAIL: $*" >&2; exit 1; }

sed -e 's@{{ fleet_mdma_url }}@https://mdma.test@' \
    -e "s@{{ fleet_auth_token | default('') }}@@" \
    -e "s@/var/log/fleet-sidecar.log@${SB}/fleet.log@" \
    -e "s@/var/lib/calimero/@${SB}/@g" \
    "${TEMPLATE}" > "${SB}/rendered.sh"

grep -q '^# --- Main loop ---$' "${SB}/rendered.sh" \
  || fail "the sidecar template no longer has a '# --- Main loop ---' marker"

sed -n '1,/^# --- Main loop ---$/p' "${SB}/rendered.sh" | sed '$d' > "${SB}/functions.sh"

if grep -q '{{\|{%' "${SB}/functions.sh"; then
  echo "FAIL: unsubstituted Jinja left in the rendered sidecar:" >&2
  grep -n '{{\|{%' "${SB}/functions.sh" >&2
  exit 1
fi

# shellcheck disable=SC1091
source "${SB}/functions.sh"

[[ "${ADMITTED_FILE}" == "${SB}/"* ]] \
  || fail "ADMITTED_FILE (${ADMITTED_FILE}) was not redirected into the sandbox"
[[ "${CONFIRMED_FILE}" == "${SB}/"* ]] \
  || fail "CONFIRMED_FILE (${CONFIRMED_FILE}) was not redirected into the sandbox"

reset() { rm -f "${ADMITTED_FILE}" "${CONFIRMED_FILE}"; }

# --- the upgrade boot: confirmed populated, admitted absent -----------------

reset
echo '["ns-alpha","ns-beta"]' > "${CONFIRMED_FILE}"
seed_admitted_from_confirmed

[[ -e "${ADMITTED_FILE}" ]] || fail "the seed did not create ${ADMITTED_FILE}"
got="$(cat "${ADMITTED_FILE}")"
for ns in ns-alpha ns-beta; do
  grep -q "${ns}" <<< "${got}" \
    || fail "seeded admitted set is missing ${ns}; a disable would never make this node leave it (got ${got})"
done

# --- idempotence: a second boot must not re-seed ----------------------------

# The node legitimately left ns-beta in the meantime. Re-seeding would put it
# back and the node would try to leave a namespace it is no longer in, forever.
echo '["ns-alpha"]' > "${ADMITTED_FILE}"
seed_admitted_from_confirmed
got="$(cat "${ADMITTED_FILE}")"
grep -q 'ns-beta' <<< "${got}" \
  && fail "the seed overwrote an existing admitted set, resurrecting a namespace the node had left (got ${got})"

# --- an empty admitted set is a real answer, not a missing one --------------

reset
echo '["ns-gamma"]' > "${CONFIRMED_FILE}"
echo '[]' > "${ADMITTED_FILE}"
seed_admitted_from_confirmed
got="$(cat "${ADMITTED_FILE}")"
[[ "${got}" == "[]" ]] \
  || fail "an existing but EMPTY admitted set was re-seeded; the guard is reading contents, not existence (got ${got})"

# --- a node that never confirmed anything seeds to empty, once --------------

reset
seed_admitted_from_confirmed
[[ -e "${ADMITTED_FILE}" ]] \
  || fail "no confirmed file must still leave an admitted file behind, or the seed runs again every boot"
got="$(cat "${ADMITTED_FILE}")"
[[ "${got}" == "[]" ]] || fail "expected an empty admitted set, got ${got}"

# --- the seed actually runs, and before the first diff ----------------------

body="$(sed -n '/^# --- Main loop ---$/,$p' "${SB}/rendered.sh")"
# `|| true` is load-bearing. Sourcing the sidecar's function half also applies
# its `set -euo pipefail` to THIS shell, so a grep that matches nothing makes
# the whole pipeline return 1 and the bare assignment aborts the script -- the
# test would still fail, but silently, with the diagnostic below never printed.
call_line="$(grep -n '^seed_admitted_from_confirmed$' <<< "${body}" | head -1 | cut -d: -f1 || true)"
loop_line="$(grep -n '^while true; do$' <<< "${body}" | head -1 | cut -d: -f1 || true)"

[[ -n "${call_line}" ]] \
  || fail "seed_admitted_from_confirmed is defined but never called; the function is dead code"
[[ -n "${loop_line}" ]] || fail "could not find the main poll loop"
(( call_line < loop_line )) \
  || fail "the seed runs at or after the poll loop (${call_line} vs ${loop_line}); the first leave diff would already have run against an empty set"

echo "PASS: the admitted set is seeded from confirmed exactly once, and never widened"
