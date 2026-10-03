#!/usr/bin/env bash
# A KMS image bakes its node allowlist into the measured kms.env, one
# `KEY=a,b,c` line per field, and the KMS release then signs that image. So the
# allowlist must be the node release's own, and every value in it must be a
# shape kms.env carries intact. A newline in a value adds a line of its own:
#
#   ALLOWED_MRTD=<96 hex>
#   ENFORCE_MEASUREMENT_POLICY=false
#
# and the later assignment wins. This runs the real
# scripts/release/kms/extract-node-allowlist.sh against a well-formed policy and
# against hostile ones, and checks verify-node-policy.sh refuses a policy that
# carries no signature before it would ever reach cosign.
#
# Usage: scripts/ci/tests/kms-node-allowlist-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
EXTRACT="${REPO_ROOT}/scripts/release/kms/extract-node-allowlist.sh"
VERIFY="${REPO_ROOT}/scripts/release/kms/verify-node-policy.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

HEX="$(printf 'ab%.0s' $(seq 48))"
failures=0

# A published-mrtds.json whose locked-read-only profile is the well-formed one,
# with `field` replaced by the JSON value `value`.
policy() {
  local field="$1" value="$2"
  jq -n --arg h "${HEX}" --arg f "${field}" --argjson v "${value}" '
    ({allowed_tcb_statuses: ["UpToDate"], allowed_mrtd: [$h],
      allowed_rtmr0: [$h], allowed_rtmr1: [$h], allowed_rtmr2: [$h], allowed_rtmr3: [$h]})
    | if $f == "" then . else .[$f] = $v end
    | {profiles: {"locked-read-only": .}}'
}

expect() {
  local want="$1" name="$2" field="$3" value="$4"
  policy "${field}" "${value}" > "${TMP}/policy.json"
  if bash "${EXTRACT}" "${TMP}/policy.json" locked-read-only "${TMP}/out.json" >/dev/null 2>&1; then
    got=accepted
  else
    got=refused
  fi
  if [[ "${got}" == "${want}" ]]; then
    echo "ok   ${name}: ${got}"
  else
    echo "FAIL ${name}: ${got}, expected ${want}"
    failures=$((failures + 1))
  fi
}

expect accepted "a well-formed allowlist" "" 'null'
expect accepted "several measurements and statuses" allowed_mrtd "[\"${HEX}\", \"${HEX^^}\"]"
expect accepted "any-case known statuses" allowed_tcb_statuses '["uptodate", "SWHardeningNeeded", "OutOfDate"]'
expect refused "a newline that adds a kms.env line" allowed_mrtd "[\"${HEX}\\nENFORCE_MEASUREMENT_POLICY=false\"]"
expect refused "a trailing newline" allowed_rtmr0 "[\"${HEX}\\n\"]"
expect refused "a comma that adds an entry" allowed_rtmr1 "[\"${HEX},${HEX}\"]"
expect refused "a short measurement" allowed_rtmr2 "[\"${HEX:1}\"]"
expect refused "a non-hex measurement" allowed_rtmr3 "[\"${HEX:1}g\"]"
expect refused "a missing field" allowed_rtmr3 'null'
expect refused "an empty field" allowed_mrtd '[]'
expect refused "a string, not a list" allowed_mrtd "\"${HEX}\""
expect refused "a non-string entry" allowed_mrtd '[1]'
expect refused "too many entries" allowed_mrtd "$(jq -n --arg h "${HEX}" '[range(33)] | map($h)')"
expect refused "a revoked status" allowed_tcb_statuses '["Revoked"]'
expect refused "an unknown status" allowed_tcb_statuses '["Anything"]'
expect refused "a status that adds a kms.env line" allowed_tcb_statuses '["uptodate\nENFORCE_MEASUREMENT_POLICY=false"]'

# The profile asked for has to exist.
policy "" 'null' > "${TMP}/policy.json"
if bash "${EXTRACT}" "${TMP}/policy.json" debug "${TMP}/out.json" >/dev/null 2>&1; then
  echo "FAIL a missing profile: accepted"
  failures=$((failures + 1))
else
  echo "ok   a missing profile: refused"
fi

# A policy without its Sigstore bundle never reaches a KMS image.
mkdir -p "${TMP}/unsigned"
cp "${TMP}/policy.json" "${TMP}/unsigned/published-mrtds.json"
if GITHUB_REPOSITORY=calimero-network/mero-tee bash "${VERIFY}" "${TMP}/unsigned" >/dev/null 2>&1; then
  echo "FAIL an unsigned policy: accepted"
  failures=$((failures + 1))
else
  echo "ok   an unsigned policy: refused"
fi

# The mero-kms role refuses the same values where kms.env is rendered, so a
# build path that skips the scripts is still held to them. The role's own tasks
# are run, not a copy. ci-workflow-lint installs ansible-core before this step,
# so there this part may not be skipped.
if command -v ansible-playbook >/dev/null 2>&1; then
  python3 - "${REPO_ROOT}" "${TMP}" <<'PY'
import sys, yaml
repo, tmp = sys.argv[1], sys.argv[2]
tasks = yaml.safe_load(open(f"{repo}/mero-tee/ansible/roles/mero-kms/tasks/main.yml"))
wanted = {"Read the node allowlist this KMS serves", "Refuse an empty node allowlist",
          "Refuse a node allowlist value kms.env could not carry intact"}
kept = [task for task in tasks if task.get("name") in wanted]
assert len(kept) == len(wanted), "the mero-kms role's allowlist tasks were renamed or removed"
yaml.safe_dump(kept, open(f"{tmp}/allowlist-tasks.yml", "w"), sort_keys=False)
open(f"{tmp}/allowlist-play.yml", "w").write(
    "- hosts: localhost\n  gather_facts: false\n  tasks:\n    - include_tasks: allowlist-tasks.yml\n")
PY
  role_expect() {
    local want="$1" name="$2" field="$3" value="$4"
    policy "${field}" "${value}" | jq '.profiles["locked-read-only"]' > "${TMP}/role-allowlist.json"
    if ansible-playbook -i localhost, -c local "${TMP}/allowlist-play.yml" \
      -e "kms_node_policy_file=${TMP}/role-allowlist.json" >"${TMP}/role.log" 2>&1; then
      got=accepted
    else
      got=refused
    fi
    if [[ "${got}" == "${want}" ]]; then
      echo "ok   role: ${name}: ${got}"
    else
      echo "FAIL role: ${name}: ${got}, expected ${want}"
      failures=$((failures + 1))
    fi
  }
  role_expect accepted "a well-formed allowlist" "" 'null'
  role_expect refused "a newline that adds a kms.env line" allowed_mrtd "[\"${HEX}\\nENFORCE_MEASUREMENT_POLICY=false\"]"
  role_expect refused "a trailing newline" allowed_rtmr0 "[\"${HEX}\\n\"]"
  role_expect refused "a comma that adds an entry" allowed_rtmr1 "[\"${HEX},${HEX}\"]"
  role_expect refused "a status that adds a kms.env line" allowed_tcb_statuses '["uptodate\nENFORCE_MEASUREMENT_POLICY=false"]'
elif [[ -n "${CI:-}" ]]; then
  echo "FAIL ansible-playbook is not installed, so the mero-kms role's checks were not run"
  failures=$((failures + 1))
else
  echo "skip the mero-kms role's checks: ansible-playbook is not installed"
fi

# And the release and probe workflows go through both scripts.
for workflow in release-kms.yaml kms-tdx-image-probe.yaml; do
  for script in extract-node-allowlist.sh verify-node-policy.sh; do
    file="${REPO_ROOT}/.github/workflows/${workflow}"
    [[ "${workflow}" == release-kms.yaml && "${script}" == verify-node-policy.sh ]] \
      && file="${REPO_ROOT}/scripts/release/kms/wait-for-node-release.sh"
    if grep -q "scripts/release/kms/${script}" "${file}"; then
      echo "ok   ${workflow} uses ${script}"
    else
      echo "FAIL ${workflow} does not use ${script}"
      failures=$((failures + 1))
    fi
  done
done

if [[ "${failures}" -gt 0 ]]; then
  echo "${failures} check(s) failed"
  exit 1
fi
echo "All node allowlist checks passed"
