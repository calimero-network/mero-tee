#!/usr/bin/env bash
# Behavioural test for the fleet sidecar's context-inventory reporting.
#
# `/api/fleet/inventory` is what makes `GET /api/cloud/contexts/{id}/relays`
# able to return anything at all (mdma#222): without this report the table it
# reads is empty and every context answers `servable: false`. The reporting side
# is the half that can be wrong quietly.
#
# Two failure directions, both silent:
#   * report a context under the WRONG group and a client is sent to a relay
#     that will refuse the write — it learns this by minting a warrant, which
#     spends a nonce it cannot get back;
#   * assemble a `full` report from PARTIAL reads and mdma prunes rows for
#     contexts this node is serving perfectly well, un-advertising a healthy
#     relay because one `meroctl` call happened to fail.
#
# Neither is reachable from the release probes: those need a live TDX node, an
# MDMA, a namespace admin publishing a capability op, and a subgroup. So this
# renders the template, sources the function half, and drives it against stubbed
# `meroctl` and `curl` — the same shape as fleet-sidecar-authorship-test.sh.
#
# Usage: scripts/ci/tests/fleet-sidecar-inventory-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
export SB

# --- render the template ---------------------------------------------------
if [[ ! -r "${TEMPLATE}" ]]; then
  echo "FAIL: cannot read ${TEMPLATE}" >&2
  exit 1
fi
# `@` as the delimiter: the auth-token placeholder contains a Jinja filter pipe.
# The state directory is redirected wholesale rather than file by file, so a
# state file added to the sidecar later cannot silently escape the sandbox.
sed -e 's@{{ fleet_mdma_url }}@https://mdma.test@' \
    -e "s@{{ fleet_auth_token | default('') }}@@" \
    -e "s@/var/log/fleet-sidecar.log@${SB}/fleet.log@" \
    -e "s@/var/lib/calimero/@${SB}/@g" \
    -e "s@/etc/vector@${SB}/vector@g" \
    -e "s@/etc/vmagent@${SB}/vmagent@g" \
    "${TEMPLATE}" > "${SB}/rendered.sh"

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
# machine or -- on a CI runner, where /var/lib/calimero does not exist -- fails
# the whole test with an error pointing at the harness rather than at the change
# that caused it. That is exactly how adding `INVENTORY_FILE` broke this test.
#
# The wholesale substitution above already covers anything under
# /var/lib/calimero; this catches a state file introduced somewhere else.
if leaked="$(grep -nE '^[A-Za-z_]+_FILE="[^"]*"' "${SB}/functions.sh" | grep -v "${SB}/")"; then
  echo "FAIL: the rendered sidecar keeps state outside the sandbox:" >&2
  echo "${leaked}" >&2
  echo "       add it to the substitution above." >&2
  exit 1
fi

# --- stubs -----------------------------------------------------------------
mkdir -p "${SB}/bin"

# `meroctl`, answering the four reads the walk makes from flat fixture files:
#   ${SB}/subgroups  "<parent>=<child>,<child>"   (absent => no children)
#   ${SB}/contexts   "<group>=<ctx>,<ctx>"        (value ERR => the read fails;
#                                                  value PAGE => a full page)
#   ${SB}/members    "<group>=<count>"            (absent => the read fails)
#   ${SB}/caps       "<group>=<mask>"             (absent => 0, core's default)
cat > "${SB}/bin/meroctl" <<'STUB'
#!/usr/bin/env bash
lookup() { grep -E "^${2}=" "${SB}/${1}" 2>/dev/null | tail -1 | cut -d= -f2-; }
emit_list() { # key, json-field, entry-template
  local raw="$1" field="$2" tmpl="$3" out="" item
  if [[ -n "${raw}" ]]; then
    IFS=',' read -ra items <<< "${raw}"
    for item in "${items[@]}"; do
      [[ -n "${out}" ]] && out+=","
      out+="${tmpl//@@/${item}}"
    done
  fi
  printf '{"%s":[%s]}\n' "${field}" "${out}"
}
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  case "${args[i]}" in
    subgroups)
      emit_list "$(lookup subgroups "${args[i + 1]}")" subgroups '{"groupId":"@@"}'
      exit 0 ;;
    contexts)
      # `group contexts list <gid>`
      raw="$(lookup contexts "${args[i + 2]}")"
      [[ "${raw}" == "ERR" ]] && exit 1
      if [[ "${raw}" == "PAGE" ]]; then
        out=""
        for ((n = 0; n < 100; n++)); do
          [[ -n "${out}" ]] && out+=","
          out+="{\"contextId\":\"c$(printf '%03d' "${n}")\"}"
        done
        printf '{"data":[%s]}\n' "${out}"
        exit 0
      fi
      emit_list "${raw}" data '{"contextId":"@@"}'
      exit 0 ;;
    get-capabilities)
      mask="$(lookup caps "${args[i + 1]}")"
      printf '{"data":{"capabilities":%s}}\n' "${mask:-0}"
      exit 0 ;;
    list)
      # `group members list <gid>` — `contexts list` is caught above.
      if [[ "${args[i - 1]}" == "members" ]]; then
        count="$(lookup members "${args[i + 1]}")"
        [[ -z "${count}" ]] && exit 1
        out=""
        for ((n = 0; n < count; n++)); do
          [[ -n "${out}" ]] && out+=","
          out+="{\"identity\":\"member$(printf '%03d' "${n}")\",\"role\":\"member\"}"
        done
        printf '{"members":[%s]}\n' "${out}"
        exit 0
      fi ;;
    show)
      [[ "${args[i - 1]}" == "account" ]] && { echo '{"data":{"accountId":"4D4D4D"}}'; exit 0; } ;;
  esac
done
exit 1
STUB

# `curl`: answers merod's `GET /admin-api/usage` from ${SB}/usage (absent =>
# the endpoint is unreachable); otherwise appends each POST body to
# ${SB}/inventory-log, or fails while ${SB}/post-fails exists so the retry path
# can be driven.
cat > "${SB}/bin/curl" <<'STUB'
#!/usr/bin/env bash
body=""
prev=""
for a in "$@"; do
  if [[ "${a}" == */admin-api/usage ]]; then
    [[ -f "${SB}/usage" ]] || exit 7
    cat "${SB}/usage"
    exit 0
  fi
  [[ "${prev}" == "-d" ]] && body="${a}"
  prev="${a}"
done
[[ -f "${SB}/post-fails" ]] && exit 22
printf '%s\n' "${body}" >> "${SB}/inventory-log"
echo '{"status":"ok"}'
STUB

chmod +x "${SB}/bin/meroctl" "${SB}/bin/curl"
PATH="${SB}/bin:${PATH}"
export PATH

# shellcheck source=/dev/null
source "${SB}/functions.sh"

# Read by the sourced sidecar, which shellcheck cannot see across the `source`.
# shellcheck disable=SC2034
EXECUTOR_ACCOUNT="4d4d4d"
: > "${SB}/subgroups"
: > "${SB}/contexts"
: > "${SB}/members"
: > "${SB}/caps"
: > "${SB}/inventory-log"

fail() { echo "FAIL: $*" >&2; exit 1; }
posts() { awk 'NF{n++} END{print n+0}' "${SB}/inventory-log"; }
expect_posts() {
  local want="$1" why="$2" got
  got="$(posts)"
  [[ "${got}" == "${want}" ]] || fail "${why} (expected ${want} posts, got ${got})"
}
last_post() { tail -1 "${SB}/inventory-log"; }
# The namespace tree used throughout: root `aa` holds context `ctx1`, subgroup
# `bb` holds `ctx2`. `bb` is where the subgroup/inheritance question lives.
echo "aa=bb" > "${SB}/subgroups"
printf 'aa=ctx1\nbb=ctx2\n' > "${SB}/contexts"
echo "aa=4" > "${SB}/members"

# 1. A subgroup's context is reported under the SUBGROUP.
#    `FleetAssignment.group_id` and `ConfirmRequest.group_id` both carry
#    namespace ids under a name that says otherwise; `InventoryGroup.group_id`
#    does not, and reporting the namespace id here would route every subgroup
#    context to a node that may refuse the write.
reconcile_inventory peer1 '["aa"]'
expect_posts 1 "a first scan must report the inventory"
groups_json="$(last_post | python3 -c "
import json, sys
ns = json.load(sys.stdin)['namespaces'][0]
print(json.dumps({g['group_id']: g for g in ns['groups']}, sort_keys=True))
")"
echo "${groups_json}" | python3 -c "
import json, sys
g = json.load(sys.stdin)
assert set(g) == {'aa', 'bb'}, g
assert g['aa']['context_ids'] == ['ctx1'], g['aa']
assert g['bb']['context_ids'] == ['ctx2'], g['bb']
" || fail "each context must be reported under its own group: ${groups_json}"

# 2. The first post is authoritative. Nothing has ever been reconciled, so the
#    periodic full pass is due immediately — otherwise a node that restarts with
#    stale rows in mdma would keep advertising them for a full interval.
[[ "$(last_post | python3 -c "import json,sys; print(json.load(sys.stdin)['full'])")" == "True" ]] \
  || fail "the first reconcile must be full: $(last_post)"

# 3. Counts ride along, and NO account id does. The node aggregates inside the
#    group's key precisely so mdma cannot hold a roster it was never sent.
last_post | python3 -c "
import json, sys
ns = json.load(sys.stdin)['namespaces'][0]
assert ns['member_count'] == 4, ns
assert ns['context_count'] == 2, ns
" || fail "member_count/context_count must be reported: $(last_post)"
grep -q 'member000' "${SB}/inventory-log" \
  && fail "an account id reached the wire: $(last_post)"

# 4. Authorship is asked PER GROUP. Core does not propagate
#    CAN_AUTHOR_ON_BEHALF through the subgroup-admit cascade, so a node holding
#    the grant on the root and nothing on the subgroup must say so — inheriting
#    it is the exact lie this endpoint exists to prevent.
echo "aa=512" > "${SB}/caps"
reconcile_inventory peer1 '["aa"]'
expect_posts 2 "a changed capability must be reported"
last_post | python3 -c "
import json, sys
g = {x['group_id']: x for x in json.load(sys.stdin)['namespaces'][0]['groups']}
assert g['aa']['authorship_ready'] is True, g['aa']
assert g['bb']['authorship_ready'] is False, g['bb']
" || fail "authorship must be per-group: $(last_post)"

# 5. Steady state is silent. The main loop runs once a second and /inventory is
#    a write; a report that has not changed must cost nothing.
reconcile_inventory peer1 '["aa"]'
reconcile_inventory peer1 '["aa"]'
expect_posts 2 "an unchanged inventory must not be re-POSTed"

# 6. THE regression that matters: a read that FAILED must not produce a `full`
#    report. mdma prunes every context row a full report does not mention, per
#    namespace — so one failed `meroctl` inside an authoritative post deletes
#    rows for contexts this node is serving, and un-advertises a healthy relay.
printf 'aa=ctx1\nbb=ERR\n' > "${SB}/contexts"
reconcile_inventory peer1 '["aa"]' true
expect_posts 3 "a partial read must still report what it could see"
last_post | python3 -c "
import json, sys
body = json.load(sys.stdin)
assert body['full'] is False, body
ns = body['namespaces'][0]
assert [g['group_id'] for g in ns['groups']] == ['aa'], ns
assert 'context_count' not in ns, ns
" || fail "a partial walk must post additively and omit the count: $(last_post)"

# 7. A page that comes back at the limit is indistinguishable from a truncated
#    one — meroctl exposes no offset/limit — so it counts as a partial read for
#    the same reason.
printf 'aa=PAGE\nbb=ctx2\n' > "${SB}/contexts"
reconcile_inventory peer1 '["aa"]' true
[[ "$(last_post | python3 -c "import json,sys; print(json.load(sys.stdin)['full'])")" == "False" ]] \
  || fail "a full page must not be reported as a complete read: $(last_post)"

# 8. A failed POST must not advance the recorded state, or the change is lost:
#    the next scan would see "nothing changed" and stay silent forever.
printf 'aa=ctx1\nbb=ctx2,ctx3\n' > "${SB}/contexts"
touch "${SB}/post-fails"
reconcile_inventory peer1 '["aa"]'
rm -f "${SB}/post-fails"
grep -q 'ctx3' "${SB}/fleet-inventory.json" \
  && fail "a failed POST must leave the recorded state unadvanced: $(cat "${SB}/fleet-inventory.json")"
reconcile_inventory peer1 '["aa"]'
grep -q 'ctx3' "${SB}/inventory-log" \
  || fail "the retry after a failed POST must happen"

# 9. A namespace mdma no longer assigns is pruned from the local record, so a
#    re-join reports from scratch rather than inheriting "already told them".
reconcile_inventory peer1 '[]'
python3 -c "
import json
state = json.load(open('${SB}/fleet-inventory.json'))
assert state['namespaces'] == {}, state
" || fail "a dropped namespace must be pruned: $(cat "${SB}/fleet-inventory.json")"

# 10. A namespace that cannot be read AT ALL is not reported. An empty report
#     would be indistinguishable from 'this node holds no contexts', and under
#     `full` that erases every row mdma has for it.
before="$(posts)"
printf 'aa=ERR\nbb=ERR\n' > "${SB}/contexts"
reconcile_inventory peer1 '["aa"]' true
expect_posts "${before}" "an unreadable namespace must not be reported at all"

# 11. An unreadable member count is absent, never zero. NULL means "no node has
#     told us"; 0 would be a lie, since a namespace always has at least its admin.
#
#     And it must NOT downgrade the post. Only a read that could hide a CONTEXT
#     blocks pruning; a missing count is a worse answer about contexts that are
#     still being reported. Conflating the two would mean a namespace whose
#     member list merely exceeds one page could never be pruned at all, so a
#     context it left would be advertised forever.
printf 'aa=ctx1\nbb=ctx2\n' > "${SB}/contexts"
: > "${SB}/members"
reconcile_inventory peer1 '["aa"]' true
last_post | python3 -c "
import json, sys
body = json.load(sys.stdin)
ns = body['namespaces'][0]
assert 'member_count' not in ns, ns
assert ns['context_count'] == 2, ns
assert body['full'] is True, body
" || fail "an unreadable member count must be omitted without blocking the prune: $(last_post)"

# 12. Same rule for the capability read: unreadable is `false` — mdma stops
#     advertising the node, the safe direction — but the context row stays and
#     the report stays authoritative.
printf 'aa=512\n' > "${SB}/caps"
echo "aa=4" > "${SB}/members"
mv "${SB}/bin/meroctl" "${SB}/bin/meroctl.real"
cat > "${SB}/bin/meroctl" <<'WRAP'
#!/usr/bin/env bash
for a in "$@"; do [[ "${a}" == "get-capabilities" ]] && exit 1; done
exec "${SB}/bin/meroctl.real" "$@"
WRAP
chmod +x "${SB}/bin/meroctl"
reconcile_inventory peer1 '["aa"]' true
mv -f "${SB}/bin/meroctl.real" "${SB}/bin/meroctl"
last_post | python3 -c "
import json, sys
body = json.load(sys.stdin)
g = {x['group_id']: x for x in body['namespaces'][0]['groups']}
assert g['aa']['authorship_ready'] is False, g['aa']
assert g['aa']['context_ids'] == ['ctx1'], g['aa']
assert body['full'] is True, body
" || fail "an unreadable capability must be false without blocking the prune: $(last_post)"

# 13. Bytes from `/admin-api/usage` ride the report, under the reported
#     namespace, renamed to the inventory's snake_case. The id is matched
#     case-insensitively: merod hex-encodes, and nothing guarantees the case the
#     assignment ledger was written in.
usage_fixture() { # total
  printf '{"namespaces":[{"namespaceId":"AA","contextCount":2,"memberCount":4,"subgroupCount":1,"bytes":{"state":%s,"privateState":1,"delta":2,"governance":3,"total":%s}},{"namespaceId":"zz","bytes":{"state":9,"privateState":9,"delta":9,"governance":9,"total":36}}]}' \
    "$(( $1 - 6 ))" "$1" > "${SB}/usage"
}
usage_fixture 1006
reconcile_inventory peer1 '["aa"]' true
last_post | python3 -c "
import json, sys
body = json.load(sys.stdin)
assert len(body['namespaces']) == 1, body
ns = body['namespaces'][0]
assert ns['bytes'] == {'state': 1000, 'private_state': 1, 'delta': 2, 'governance': 3, 'total': 1006}, ns
assert body['full'] is True, body
" || fail "usage bytes must be attached to the reported namespace: $(last_post)"
grep -q '"zz"' "${SB}/inventory-log" \
  && fail "usage for a namespace this node was not asked about must not be reported: $(last_post)"

# 14. Bytes alone do not make a change. The estimate moves with every write and
#     compaction; comparing it would post on every scan.
before="$(posts)"
usage_fixture 5006
reconcile_inventory peer1 '["aa"]'
expect_posts "${before}" "a bytes-only change must not trigger a post"

# 15. ...but they ride the next post that happens anyway, so the periodic full
#     pass bounds how stale mdma's number can get.
reconcile_inventory peer1 '["aa"]' true
last_post | python3 -c "
import json, sys
assert json.load(sys.stdin)['namespaces'][0]['bytes']['total'] == 5006
" || fail "the full pass must carry the current bytes: $(last_post)"

# 16. An unreachable `/usage` omits the bytes and changes nothing else: the
#     report is still posted and still authoritative. Bytes say nothing about
#     which contexts exist, so they must never block a prune.
rm -f "${SB}/usage"
reconcile_inventory peer1 '["aa"]' true
last_post | python3 -c "
import json, sys
body = json.load(sys.stdin)
ns = body['namespaces'][0]
assert 'bytes' not in ns, ns
assert body['full'] is True, body
assert ns['context_count'] == 2, ns
" || fail "an unreachable /usage must omit bytes without downgrading the post: $(last_post)"

# 17. A malformed breakdown is dropped, not half-reported: a namespace missing
#     a column would read as a real, smaller number.
printf '{"namespaces":[{"namespaceId":"aa","bytes":{"state":1,"total":1}}]}' > "${SB}/usage"
reconcile_inventory peer1 '["aa"]' true
last_post | python3 -c "
import json, sys
assert 'bytes' not in json.load(sys.stdin)['namespaces'][0]
" || fail "a partial byte breakdown must be omitted: $(last_post)"
rm -f "${SB}/usage"

echo "OK: fleet sidecar context inventory — 17 checks, $(posts) posts sent"
