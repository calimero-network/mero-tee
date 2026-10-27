#!/usr/bin/env bash
# Behavioural test for the fleet sidecar's namespace switch: running mdma's
# `switch` instructions, and reporting the versions that tell mdma it worked.
#
# An application id is the same for every release of an app, so the id alone
# can never show a replica is behind: the instruction and the inventory both
# carry versions, and `running_version` is the only completion signal mdma gets.
# Renders the template, sources the function half and drives it against stubbed
# `meroctl` and `curl`, the same shape as fleet-sidecar-inventory-test.sh.
#
# Usage: scripts/ci/tests/fleet-sidecar-switch-test.sh
# SWITCH_NEXT_TRY is the sourced sidecar's retry state, which shellcheck cannot see.
# shellcheck disable=SC2034
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
export SB

[[ -r "${TEMPLATE}" ]] || { echo "FAIL: cannot read ${TEMPLATE}" >&2; exit 1; }
sed -e 's@{{ fleet_mdma_url }}@https://mdma.test@' \
    -e "s@{{ fleet_auth_token | default('') }}@@" \
    -e "s@/run/calimero/fleet-sidecar.log@${SB}/fleet.log@" \
    -e "s@/mnt/data/fleet/@${SB}/@g" \
    -e "s@/etc/vector@${SB}/vector@g" \
    -e "s@/etc/vmagent@${SB}/vmagent@g" \
    "${TEMPLATE}" > "${SB}/rendered.sh"
grep -q '^# --- Main loop ---$' "${SB}/rendered.sh" \
  || { echo "FAIL: the sidecar template lost its '# --- Main loop ---' marker" >&2; exit 1; }
sed -n '1,/^# --- Main loop ---$/p' "${SB}/rendered.sh" | sed '$d' > "${SB}/functions.sh"

mkdir -p "${SB}/bin"

# `meroctl`: logs every call to ${SB}/meroctl-log, and answers
#   app list-versions  from ${SB}/installed (JSON; absent => the read fails)
#   group upgrade activate  exits ${SB}/activate-rc (default 0)
#   group contexts list <gid>  from ${SB}/ctx-<gid> (comma list of context ids)
cat > "${SB}/bin/meroctl" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${SB}/meroctl-log"
case "$*" in
  *"app list-versions"*)
    [[ -f "${SB}/installed" ]] || exit 1
    cat "${SB}/installed"; exit 0 ;;
  *"app install"*) exit 0 ;;
  *"group upgrade activate"*) exit "$(cat "${SB}/activate-rc" 2>/dev/null || echo 0)" ;;
  *"group subgroups"*) echo '{"subgroups":[]}'; exit 0 ;;
  *"group contexts list"*)
    gid="${*: -1}"
    raw="$(cat "${SB}/ctx-${gid}" 2>/dev/null || true)"
    out=""
    IFS=',' read -ra ids <<< "${raw}"
    for id in "${ids[@]}"; do
      [[ -z "${id}" ]] && continue
      [[ -n "${out}" ]] && out+=","
      out+="{\"contextId\":\"${id}\"}"
    done
    printf '{"data":[%s]}\n' "${out}"; exit 0 ;;
esac
exit 1
STUB

# `curl`: GET /admin-api/groups/<ns>/upgrade/status from ${SB}/status.json
# (absent => no missingReleases field; ${SB}/status-fail => the read fails), GET /admin-api/groups/<ns> from ${SB}/group.json, GET
# /admin-api/contexts from ${SB}/contexts.json (each absent => the read fails);
# any POST body is appended to ${SB}/inventory-log.
cat > "${SB}/bin/curl" <<'STUB'
#!/usr/bin/env bash
body=""; prev=""
for a in "$@"; do
  printf '%s\n' "${a}" >> "${SB}/curl-log"
  case "${a}" in
    */admin-api/groups/*/members\?*) exit 22 ;;
    */admin-api/groups/*/upgrade/status) [[ ! -f "${SB}/status-fail" ]] || exit 22; cat "${SB}/status.json" 2>/dev/null || echo '{"data":null}'; exit 0 ;;
    */admin-api/groups/*) [[ -f "${SB}/group.json" ]] || exit 22; cat "${SB}/group.json"; exit 0 ;;
    */admin-api/contexts) [[ -f "${SB}/contexts.json" ]] || exit 22; cat "${SB}/contexts.json"; exit 0 ;;
    */admin-api/usage) exit 7 ;;
  esac
  if [[ "${prev}" == "-d" ]]; then body="${a}"; [[ "${body}" != "@-" ]] || body=$(cat); fi
  prev="${a}"
done
printf '%s\n' "${body}" >> "${SB}/inventory-log"
echo '{"status":"ok"}'
STUB
# `timeout`: budgets are not under test, and not every dev machine ships it.
cat > "${SB}/bin/timeout" <<'STUB'
#!/usr/bin/env bash
shift 3
exec "$@"
STUB
chmod +x "${SB}/bin/meroctl" "${SB}/bin/curl" "${SB}/bin/timeout"
PATH="${SB}/bin:${PATH}"
export PATH

# shellcheck source=/dev/null
source "${SB}/functions.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
reset() { : > "${SB}/meroctl-log"; : > "${SB}/curl-log"; : > "${SB}/fleet.log"; rm -f "${SB}/installed" "${SB}/activate-rc" "${SB}/status.json" "${SB}/status-fail"; SWITCH_NEXT_TRY=(); }
calls() { grep -c -- "$1" "${SB}/meroctl-log" || true; }

NS="$(printf 'aa%.0s' {1..32})"
APP="AppIdXyz"
group_json() { printf '{"data":{"targetApplicationId":"%s","appPackage":"com.example.app","appVersion":"%s"}}' "$APP" "$1" > "${SB}/group.json"; }
answer() { # intent version
  printf '{"assignments":[],"switch":[{"intent_id":"%s","namespace_id":"%s","target_application_id":"%s","target_version":"%s"}]}' "$1" "$NS" "$APP" "$2"
}

# 1. Target release missing: install it, then activate with BOTH expectations,
#    in that order.
reset; group_json 2.0.0
echo '{"versions":["1.0.0"]}' > "${SB}/installed"
reconcile_switch "$(answer i1 2.0.0)"
grep -q -e "app install com.example.app@2.0.0\$" "${SB}/meroctl-log" \
  || fail "a missing release must be installed: $(cat "${SB}/meroctl-log")"
want="group upgrade activate ${NS} --expect-application-id ${APP} --expect-version 2.0.0"
grep -q -e "${want}\$" "${SB}/meroctl-log" || fail "activate must carry both expectations: $(cat "${SB}/meroctl-log")"
[[ "$(grep -n 'app install' "${SB}/meroctl-log" | head -1 | cut -d: -f1)" -lt "$(grep -n 'upgrade activate' "${SB}/meroctl-log" | head -1 | cut -d: -f1)" ]] \
  || fail "install must come before activate"

# 2. Already installed: no install.
reset; group_json 2.0.0
echo '{"versions":["1.0.0","2.0.0"]}' > "${SB}/installed"
reconcile_switch "$(answer i2 2.0.0)"
[[ "$(calls 'app install')" == 0 ]] || fail "an installed release must not be installed again"
[[ "$(calls 'upgrade activate')" == 1 ]] || fail "an installed release must be activated once"

# 2a. Two missed upgrades: every missing release is installed oldest first,
#     target included, before the activate.
reset; group_json 3.0.0
echo '{"versions":["1.0.0","2.0.0","3.0.0"]}' > "${SB}/installed"
echo '{"data":null,"missingReleases":[{"package":"com.example.app","version":"2.0.0","applicationId":"x"},{"package":"com.example.app","version":"3.0.0","applicationId":"x"}]}' > "${SB}/status.json"
reconcile_switch "$(answer i2a 3.0.0)"
[[ "$(awk '/ app install |upgrade activate/ { for (i = 1; i <= NF; i++) if ($i == "app" || $i == "group") { print $i, $(i+1), $(i+2); break } }' "${SB}/meroctl-log")" == "$(printf 'app install com.example.app@2.0.0\napp install com.example.app@3.0.0\ngroup upgrade activate' )" ]] \
  || fail "missing releases must install oldest first, then activate: $(cat "${SB}/meroctl-log")"

# 2b. An unreadable upgrade status: nothing installed or activated, retried later.
reset; group_json 2.0.0
echo '{"versions":["1.0.0"]}' > "${SB}/installed"
: > "${SB}/status-fail"
reconcile_switch "$(answer i2b 2.0.0)"
[[ "$(calls 'app install')" == 0 && "$(calls 'upgrade activate')" == 0 ]] || fail "a failed status read must not install or activate: $(cat "${SB}/meroctl-log")"
grep -q "WARN: switch of ${NS}: could not read" "${SB}/fleet.log" || fail "a failed status read must be logged: $(cat "${SB}/fleet.log")"

# 3. A failed activate (409, or anything else) is logged and not retried within
#    the poll interval; a later poll retries it.
reset; group_json 2.0.0
echo '{"versions":["2.0.0"]}' > "${SB}/installed"
echo 1 > "${SB}/activate-rc"
reconcile_switch "$(answer i3 2.0.0)"
reconcile_switch "$(answer i3 2.0.0)"
[[ "$(calls 'upgrade activate')" == 1 ]] || fail "a failed activate must not be retried straight away"
grep -q "WARN: switch of ${NS}: activate failed" "${SB}/fleet.log" || fail "a failed activate must be logged: $(cat "${SB}/fleet.log")"
SWITCH_NEXT_TRY=()
reconcile_switch "$(answer i3 2.0.0)"
[[ "$(calls 'upgrade activate')" == 2 ]] || fail "a later poll must retry the activate"

# 4. The namespace's target moved since mdma asked: log, activate nothing.
reset; group_json 3.0.0
echo '{"versions":["2.0.0"]}' > "${SB}/installed"
reconcile_switch "$(answer i4 2.0.0)"
[[ "$(calls 'upgrade activate')" == 0 ]] || fail "a moved target must not be activated"
grep -q "moved" "${SB}/fleet.log" || fail "a moved target must be logged: $(cat "${SB}/fleet.log")"

# 5. No switch field, an empty one, or a malformed entry: nothing is called.
reset; group_json 2.0.0
reconcile_switch '{"assignments":[]}'
reconcile_switch '{"assignments":[],"switch":[]}'
reconcile_switch '{"assignments":[],"switch":null}'
reconcile_switch '{"assignments":[],"switch":[{"intent_id":"x","namespace_id":"zz","target_application_id":"a","target_version":"1"}]}'
[[ ! -s "${SB}/meroctl-log" && ! -s "${SB}/curl-log" ]] || fail "no instruction must change nothing: $(cat "${SB}/meroctl-log" "${SB}/curl-log")"

# --- inventory: target and running versions --------------------------------
running_for() { # contexts.json body; prints the group's inventory entry
  reset; group_json 2.0.0
  printf '%s' "$1" > "${SB}/contexts.json"
  printf 'c1,c2' > "${SB}/ctx-${NS}"
  collect_namespace_inventory "${NS}" | python3 -c "
import json, sys
print(json.dumps(json.load(sys.stdin)['namespace']['groups'][0], sort_keys=True))"
}
ctxs() { # version...
  local out="" n=0 v
  for v in "$@"; do
    n=$((n + 1)); [[ -n "${out}" ]] && out+=","
    if [[ "${v}" == "-" ]]; then out+="{\"id\":\"c${n}\",\"groupId\":\"${NS}\"}"
    else out+="{\"id\":\"c${n}\",\"groupId\":\"${NS}\",\"applicationVersion\":\"${v}\"}"; fi
  done
  printf '{"data":{"contexts":[%s]}}' "${out}"
}
field() { python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1]).get(sys.argv[2], 'ABSENT')))" "$1" "$2"; }

# 6. Equal versions: that version; the group's stored target rides along.
g="$(running_for "$(ctxs 2.0.0 2.0.0)")"
[[ "$(field "$g" running_version)" == '"2.0.0"' ]] || fail "equal versions: $g"
[[ "$(field "$g" target_version)" == '"2.0.0"' ]] || fail "target_version: $g"
[[ "$(field "$g" target_application_id)" == "\"${APP}\"" ]] || fail "target_application_id: $g"

# 7. Differing versions: the lowest by semver, not by string.
g="$(running_for "$(ctxs 1.10.0 1.9.0)")"
[[ "$(field "$g" running_version)" == '"1.9.0"' ]] || fail "lowest semver, not string order: $g"
g="$(running_for "$(ctxs 2.0.0 2.0.0-rc.1)")"
[[ "$(field "$g" running_version)" == '"2.0.0-rc.1"' ]] || fail "a prerelease is lower than its release: $g"

# 8. This node holds none of the group's contexts: null.
g="$(running_for '{"data":{"contexts":[]}}')"
[[ "$(field "$g" running_version)" == 'null' ]] || fail "no contexts held must report null: $g"

# 9. Unreadable contexts or group: the field is absent, never a guess.
reset; rm -f "${SB}/contexts.json" "${SB}/group.json"; printf 'c1' > "${SB}/ctx-${NS}"
g="$(collect_namespace_inventory "${NS}" | python3 -c "
import json, sys
print(json.dumps(json.load(sys.stdin)['namespace']['groups'][0], sort_keys=True))")"
for k in running_version target_version target_application_id; do
  [[ "$(field "$g" "$k")" == '"ABSENT"' ]] || fail "unreadable reads must omit ${k}: $g"
done

echo "OK: fleet sidecar namespace switch - all checks passed"
