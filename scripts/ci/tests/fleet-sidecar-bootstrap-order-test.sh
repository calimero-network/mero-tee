#!/usr/bin/env bash
# A node with no fleet token must still be able to register.
#
# `/api/fleet/should-join` requires a fleet token. A node is ISSUED one by
# registering, and `/api/fleet/nodes/register` is a bootstrap route that takes
# none. So the order of those two inside the reconcile loop decides whether a
# fresh node can ever join the fleet at all:
#
#   poll first  -> 401 -> `continue` -> registration never runs -> no token
#                  -> poll 401s forever. A closed loop, and a SILENT one:
#                  `poll_mdma` returns 1 with no output by design, so the node
#                  logs nothing after startup while looking healthy from
#                  outside (merod serving, correct image, MRTD allowlisted).
#
#   register first -> token issued -> poll succeeds -> everything else runs.
#
# This was unreachable while the image carried a baked fleet token: `FLEET_TOKEN`
# was already set, the first poll succeeded, and the loop fell through. Removing
# that secret from the image left the ordering behind, and every node created
# after it stopped registering.
#
# Checked structurally rather than behaviourally: the loop is a single `while
# true` in a script with no entry point to call, and what matters is an ORDER,
# which a static read states more directly than a simulated run would.
#
# Usage: scripts/ci/tests/fleet-sidecar-bootstrap-order-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

fail() { echo "FAIL: $*" >&2; exit 1; }

[[ -r "$TEMPLATE" ]] || fail "cannot read ${TEMPLATE}"

# The loop body only; the function definitions above it mention these names too.
body="$(sed -n '/^# --- Main loop ---$/,$p' "$TEMPLATE")"

line_of() { # first line number in the loop body matching a fixed string
  grep -nF -- "$1" <<<"$body" | head -1 | cut -d: -f1
}

# Single quotes are deliberate: these are the LITERAL strings to find in the
# template, `$PEER_ID` and all. Expanding them here would search for the value
# of a variable this script does not have.
# shellcheck disable=SC2016
reg=$(line_of 'reconcile_registration "$PEER_ID"')
# shellcheck disable=SC2016
poll=$(line_of 'if ! response=$(poll_mdma')
acct=$(line_of 'reconcile_executor_account')

[[ -n "$reg"  ]] || fail "reconcile_registration is not called in the main loop"
[[ -n "$poll" ]] || fail "the poll gate was not found; this test slices on it"
[[ -n "$acct" ]] || fail "reconcile_executor_account is not called in the main loop"

(( reg < poll )) || fail "reconcile_registration (line ${reg} of the loop) runs AFTER the
       should-join gate (line ${poll}). A node with no fleet token gets 401 there,
       \`continue\`s, and never reaches registration -- so it is never issued the
       token the poll needs. Registration must come FIRST."

(( acct < reg )) || fail "reconcile_executor_account (line ${acct}) must run before
       reconcile_registration (line ${reg}); registration cannot bind an identity
       without the executor account and returns early without one."

# The gate must still exist and still `continue` -- the safety property it was
# written for (never mutate state on a failed poll) has to survive the reorder.
grep -qF 'continue' <<<"$(sed -n "${poll},$((poll + 40))p" <<<"$body")" \
  || fail "the poll gate no longer \`continue\`s on failure; a failed poll must not
       fall through into the join/leave logic"

echo "PASS: registration (loop line ${reg}) runs before the should-join gate (line ${poll})"
