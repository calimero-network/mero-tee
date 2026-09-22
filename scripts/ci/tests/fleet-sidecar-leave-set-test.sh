#!/usr/bin/env bash
# The leave diff must follow what this node was ADMITTED to, not what mdma
# acknowledged.
#
# Disabling fleet HA makes a namespace vanish from `/api/fleet/should-join`,
# and the sidecar reads that as "leave this namespace": it runs
# `meroctl namespace leave`, which publishes `MemberLeft` and irreversibly
# purges the local keys.
#
# The set it diffs against decides whether that ever happens. A namespace
# enters `confirmed` only when the local `fleet-join` AND mdma's `/confirm`
# BOTH succeed. So a join that lands while the `/confirm` is raced by the
# disable itself leaves the node a p2p member of a namespace that is in
# NEITHER set -- and `confirmed - desired` is empty for it, so it is never
# left. The node keeps the namespace's key and stays a `ReadOnlyTee` member of
# the owner's group indefinitely, which is precisely the prod state recorded in
# calimero-network/mdma#155 (`confirmed_at = NULL`, assignment still held).
#
# Diffing against the ADMITTED set closes it: admission is recorded the moment
# the local join succeeds, before `/confirm` is attempted, because that file
# answers "what must this node leave if it stops being entitled" -- a question
# about p2p membership, not about mdma's bookkeeping.
#
# Asserted against the template's own text rather than by running the poll
# loop, which needs a live merod and an mdma. The other sidecar tests that
# source the function half do so because they exercise functions; this is about
# which SET the loop reads, so it reads the loop.
#
# Usage: scripts/ci/tests/fleet-sidecar-leave-set-test.sh

# Every pattern here greps the TEMPLATE for literal shell text, so `$group_id`
# and `$confirmed` must stay unexpanded -- expanding them is exactly what would
# make the checks vacuous. File-level, before the first command, because the
# patterns appear throughout.
# shellcheck disable=SC2016
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

if [[ ! -r "${TEMPLATE}" ]]; then
  echo "FAIL: cannot read ${TEMPLATE}" >&2
  exit 1
fi

fail() { echo "FAIL: $*" >&2; exit 1; }

# Comments describe intent; they must not satisfy a check about behaviour.
code="$(grep -v '^[[:space:]]*#' "${TEMPLATE}")"

# --- the admitted set exists and is persisted ------------------------------

grep -q 'ADMITTED_FILE=' <<< "${code}" \
  || fail "no ADMITTED_FILE: the leave set has nowhere to come from"

for fn in load_admitted save_admitted note_admitted; do
  grep -qE "^${fn}\(\)" <<< "${code}" \
    || fail "${fn} is missing; the admitted set cannot be read or written"
done

# --- admission is recorded BEFORE, and independently of, /confirm ----------

# `note_admitted` must sit between the successful join and the confirm attempt.
join_line="$(grep -n 'if join_group "\$group_id"; then' <<< "${code}" | head -1 | cut -d: -f1)"
note_line="$(grep -n 'note_admitted "\$group_id"' <<< "${code}" | head -1 | cut -d: -f1)"
# The confirm that FOLLOWS the join, not the unrelated earlier call inside
# `reconcile_authorship` -- taking the first match in the file compared the
# wrong pair and made this check pass or fail for the wrong reason.
confirm_line="$(grep -n 'if confirm_assignment ' <<< "${code}" | awk -F: -v n="${note_line}" '$1 > n {print $1; exit}')"

[[ -n "${join_line}" && -n "${note_line}" && -n "${confirm_line}" ]] \
  || fail "could not locate the join / note_admitted / confirm sequence"

(( note_line > join_line )) \
  || fail "note_admitted must run AFTER the join succeeds, not before"
(( note_line < confirm_line )) \
  || fail "note_admitted must run BEFORE confirm_assignment -- recording it only on a \
successful /confirm is the bug: a raced confirm then leaves an admitted namespace \
unleavable"

# `note_admitted` must not be nested inside the confirm's success branch, which
# would make it conditional on mdma again by another route.
awk_out="$(awk -v n="${note_line}" 'NR==n {print}' <<< "${code}")"
grep -qE '^[[:space:]]{6}note_admitted' <<< "${awk_out}" \
  || fail "note_admitted is not at the join branch's indentation, so it is probably \
gated on something else: ${awk_out}"

# --- the leave diff reads the admitted set ---------------------------------

leave_block="$(sed -n '/to_leave=\$(python3/,/^" 2>/p' <<< "${code}")"
[[ -n "${leave_block}" ]] || fail "could not find the to_leave computation"

grep -q 'load_admitted' <<< "${leave_block}" \
  || fail "the leave diff does not read the admitted set"
grep -q 'sorted(adm - des)' <<< "${leave_block}" \
  || fail "the leave diff is not ADMITTED - desired"
grep -q '\$confirmed' <<< "${leave_block}" \
  && fail "the leave diff still reads \$confirmed; a namespace mdma never acknowledged \
would still be unleavable"

# --- the admitted set is pruned, or every poll re-leaves forever -----------

grep -q 'save_admitted "\$(python3' <<< "${code}" \
  || fail "the admitted set is never pruned; a left namespace would be re-left every poll"
grep -q 'sorted(adm & des)' <<< "${code}" \
  || fail "the admitted prune is not an intersection with desired"

# The prune must come AFTER the leave, or the diff loses its entries first.
leave_call_line="$(grep -n 'leave_group "\$group_id"' <<< "${code}" | tail -1 | cut -d: -f1)"
prune_line="$(grep -n 'save_admitted "\$(python3' <<< "${code}" | head -1 | cut -d: -f1)"
(( prune_line > leave_call_line )) \
  || fail "the admitted set is pruned before the leave runs, so nothing is ever left"

# --- confirmed keeps its own job -------------------------------------------

# The /confirm retry depends on a namespace staying OUT of `confirmed` until
# mdma acknowledges it. If the admitted set were merged into it, the retry
# would stop firing.
grep -q 'save_confirmed "\$confirmed"' <<< "${code}" \
  || fail "the confirmed set is no longer persisted; the /confirm retry is broken"

echo "PASS: the leave diff follows admission, not mdma's acknowledgement"
