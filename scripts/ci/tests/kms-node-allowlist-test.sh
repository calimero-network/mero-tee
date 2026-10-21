#!/usr/bin/env bash
# A KMS image bakes its node allowlist, and optionally its agent allowlist, into
# the measured kms.env, one `KEY=a,b,c` line per field, and the KMS release then
# signs that image. So the node allowlist must be the node release's own, and
# every value in either must be a shape kms.env carries intact. A newline in a
# value adds a line of its own:
#
#   ALLOWED_MRTD=<96 hex>
#   ENFORCE_MEASUREMENT_POLICY=false
#
# and the later assignment wins. This runs the real
# scripts/release/kms/extract-node-allowlist.sh against a well-formed policy and
# against hostile ones (and its --check mode, which the agent allowlist goes
# through), checks verify-node-policy.sh refuses a policy that carries no
# signature before it would ever reach cosign, and runs the mero-kms role's own
# asserts both through render_role_tree.py (the mkosi build) and ansible-playbook.
#
# Usage: scripts/ci/tests/kms-node-allowlist-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
EXTRACT="${REPO_ROOT}/scripts/release/kms/extract-node-allowlist.sh"
VERIFY="${REPO_ROOT}/scripts/release/kms/verify-node-policy.sh"
RENDER="${REPO_ROOT}/scripts/image/render_role_tree.py"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

HEX="$(printf 'ab%.0s' $(seq 48))"
INJECTED="[\"${HEX}\\nENFORCE_MEASUREMENT_POLICY=false\"]"
failures=0

report() {
  local want="$1" got="$2" name="$3"
  if [[ "${got}" == "${want}" ]]; then
    echo "ok   ${name}: ${got}"
  else
    echo "FAIL ${name}: ${got}, expected ${want}"
    failures=$((failures + 1))
  fi
}

# A well-formed allowlist with `field` replaced by the JSON value `value`.
allowlist() {
  local field="$1" value="$2"
  jq -n --arg h "${HEX}" --arg f "${field}" --argjson v "${value}" '
    {allowed_tcb_statuses: ["UpToDate"], allowed_mrtd: [$h],
     allowed_rtmr0: [$h], allowed_rtmr1: [$h], allowed_rtmr2: [$h], allowed_rtmr3: [$h]}
    | if $f == "" then . elif $v == null then del(.[$f]) else .[$f] = $v end'
}

# A published-mrtds.json whose locked-read-only profile is that allowlist.
policy() {
  allowlist "$1" "$2" | jq '{profiles: {"locked-read-only": .}}'
}

expect() {
  local want="$1" name="$2" field="$3" value="$4" got
  policy "${field}" "${value}" > "${TMP}/policy.json"
  if bash "${EXTRACT}" "${TMP}/policy.json" locked-read-only "${TMP}/out.json" >/dev/null 2>&1; then
    got=accepted
  else
    got=refused
  fi
  report "${want}" "${got}" "${name}"
}

expect accepted "a well-formed allowlist" "" 'null'
expect accepted "several measurements and statuses" allowed_mrtd "[\"${HEX}\", \"${HEX^^}\"]"
expect accepted "any-case known statuses" allowed_tcb_statuses '["uptodate", "SWHardeningNeeded", "OutOfDate"]'
expect refused "a newline that adds a kms.env line" allowed_mrtd "${INJECTED}"
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

# The extracted file is the profile's six fields, values untouched.
policy "" 'null' > "${TMP}/policy.json"
bash "${EXTRACT}" "${TMP}/policy.json" locked-read-only "${TMP}/out.json" >/dev/null 2>&1 || true
if [[ -s "${TMP}/out.json" ]] && diff <(allowlist "" 'null' | jq -S .) <(jq -S . "${TMP}/out.json") >/dev/null; then
  report extracted extracted "the profile's allowlist, as published"
else
  report extracted "not extracted" "the profile's allowlist, as published"
fi

# The profile asked for has to exist.
if bash "${EXTRACT}" "${TMP}/policy.json" debug "${TMP}/out.json" >/dev/null 2>&1; then
  report refused accepted "a missing profile"
else
  report refused refused "a missing profile"
fi

# --check holds an allowlist file (the agent's) to the same shapes.
check_expect() {
  local want="$1" name="$2" field="$3" value="$4" got
  allowlist "${field}" "${value}" > "${TMP}/agent.json"
  if bash "${EXTRACT}" --check "${TMP}/agent.json" >/dev/null 2>&1; then
    got=accepted
  else
    got=refused
  fi
  report "${want}" "${got}" "--check: ${name}"
}
check_expect accepted "a well-formed allowlist" "" 'null'
check_expect refused "a newline that adds a kms.env line" allowed_rtmr3 "${INJECTED}"
check_expect refused "a comma that adds an entry" allowed_mrtd "[\"${HEX},${HEX}\"]"
check_expect refused "a missing field" allowed_rtmr2 'null'

# A policy without its Sigstore bundle never reaches a KMS image.
mkdir -p "${TMP}/unsigned"
cp "${TMP}/policy.json" "${TMP}/unsigned/published-mrtds.json"
if GITHUB_REPOSITORY=calimero-network/mero-tee bash "${VERIFY}" "${TMP}/unsigned" >/dev/null 2>&1; then
  report refused accepted "an unsigned policy"
else
  report refused refused "an unsigned policy"
fi

# The mero-kms role refuses the same values where kms.env is rendered, so a
# build path that skips the scripts is still held to them. The role's own tasks
# are run, not a copy: through render_role_tree.py, as the mkosi build renders
# them, and through ansible-playbook.
echo stub > "${TMP}/mero-kms"
role_cases=(
  "accepted|a well-formed allowlist|node||null"
  "accepted|a well-formed agent allowlist|agent||null"
  "refused|a newline that adds a kms.env line|node|allowed_mrtd|${INJECTED}"
  "refused|a trailing newline|node|allowed_rtmr0|[\"${HEX}\\n\"]"
  "refused|a comma that adds an entry|node|allowed_rtmr1|[\"${HEX},${HEX}\"]"
  "refused|a status that adds a kms.env line|node|allowed_tcb_statuses|[\"uptodate\\nENFORCE_MEASUREMENT_POLICY=false\"]"
  "refused|a string, not a list|node|allowed_rtmr2|\"${HEX}\""
  "refused|an agent newline that adds a kms.env line|agent|allowed_rtmr3|${INJECTED}"
  "refused|an agent comma that adds an entry|agent|allowed_mrtd|[\"${HEX},${HEX}\"]"
  "refused|an agent short measurement|agent|allowed_rtmr1|[\"${HEX:1}\"]"
)
# Writes node.json and agent.json for a case; prints the agent file to pass.
role_inputs() {
  local which="$1" field="$2" value="$3"
  allowlist "" 'null' > "${TMP}/role-node.json"
  if [[ "${which}" == node ]]; then
    allowlist "${field}" "${value}" > "${TMP}/role-node.json"
    echo ""
  else
    allowlist "${field}" "${value}" > "${TMP}/role-agent.json"
    echo "${TMP}/role-agent.json"
  fi
}

if python3 -c 'import jinja2, yaml' 2>/dev/null; then
  for case in "${role_cases[@]}"; do
    IFS='|' read -r want name which field value <<< "${case}"
    agent_file="$(role_inputs "${which}" "${field}" "${value}")"
    rm -rf "${TMP}/render"
    if python3 "${RENDER}" "${REPO_ROOT}/mero-tee/playbook-kms.yml" --out "${TMP}/render" \
      --manifest "${TMP}/render.json" --cache "${TMP}/empty" \
      -e lockdown_profile=locked-read-only -e image_version=0.0.0 \
      -e "mero_kms_binary=${TMP}/mero-kms" -e "kms_node_policy_file=${TMP}/role-node.json" \
      -e "kms_agent_policy_file=${agent_file}" --role mero-kms >"${TMP}/render.log" 2>&1; then
      got=accepted
    else
      got=refused
    fi
    report "${want}" "${got}" "render_role_tree: ${name}"
  done
elif [[ -n "${CI:-}" ]]; then
  report ran "not run" "render_role_tree: python3 jinja2/yaml missing"
else
  echo "skip the mero-kms role through render_role_tree.py: python3 jinja2/yaml not installed"
fi

# ci-workflow-lint installs ansible-core before this step, so there this part
# may not be skipped.
if command -v ansible-playbook >/dev/null 2>&1; then
  python3 - "${REPO_ROOT}" "${TMP}" <<'PY'
import sys, yaml
repo, tmp = sys.argv[1], sys.argv[2]
tasks = yaml.safe_load(open(f"{repo}/mero-tee/ansible/roles/mero-kms/tasks/main.yml"))
wanted = {"Read the node allowlist this KMS serves", "Refuse an empty node allowlist",
          "Refuse a node allowlist value kms.env could not carry intact",
          "Read the agent allowlist this KMS serves", "Refuse an empty agent allowlist",
          "Refuse an agent allowlist value kms.env could not carry intact"}
kept = [task for task in tasks if task.get("name") in wanted]
assert len(kept) == len(wanted), "the mero-kms role's allowlist tasks were renamed or removed"
yaml.safe_dump(kept, open(f"{tmp}/allowlist-tasks.yml", "w"), sort_keys=False)
open(f"{tmp}/allowlist-play.yml", "w").write(
    "- hosts: localhost\n  gather_facts: false\n  tasks:\n    - include_tasks: allowlist-tasks.yml\n")
PY
  for case in "${role_cases[@]}"; do
    IFS='|' read -r want name which field value <<< "${case}"
    agent_file="$(role_inputs "${which}" "${field}" "${value}")"
    if ansible-playbook -i localhost, -c local "${TMP}/allowlist-play.yml" \
      -e "kms_node_policy_file=${TMP}/role-node.json" -e "kms_agent_policy_file=${agent_file}" \
      >"${TMP}/role.log" 2>&1; then
      got=accepted
    else
      got=refused
    fi
    report "${want}" "${got}" "ansible-playbook: ${name}"
  done
elif [[ -n "${CI:-}" ]]; then
  report ran "not run" "ansible-playbook is not installed, so the mero-kms role's checks"
else
  echo "skip the mero-kms role under ansible-playbook: ansible-playbook is not installed"
fi

# And every workflow that builds a KMS image goes through both scripts.
uses() {
  local file="$1" pattern="$2" name="$3"
  if grep -q -- "${pattern}" "${REPO_ROOT}/${file}"; then
    report uses uses "${name}"
  else
    report uses "does not use" "${name}"
  fi
}
uses scripts/release/kms/wait-for-node-release.sh "scripts/release/kms/verify-node-policy.sh" \
  "Release mero-kms verifies the node policy (wait-for-node-release.sh)"
uses .github/workflows/release-kms.yaml "scripts/release/kms/extract-node-allowlist.sh \\\\$" \
  "Release mero-kms extracts the node allowlist through the script"
uses .github/workflows/release-kms.yaml "scripts/release/kms/extract-node-allowlist.sh --check build/agent-allowlist.json" \
  "Release mero-kms checks the agent allowlist"
uses .github/workflows/node-image-mkosi.yaml "scripts/release/kms/verify-node-policy.sh" \
  "Image (mkosi) verifies the node policy"
uses .github/workflows/node-image-mkosi.yaml "scripts/release/kms/extract-node-allowlist.sh" \
  "Image (mkosi) extracts the node allowlist through the script"
for workflow in release-kms.yaml node-image-mkosi.yaml; do
  if grep -q "'.profiles\[\$p\]" "${REPO_ROOT}/.github/workflows/${workflow}"; then
    report "no inline extraction" "inline extraction" "${workflow}"
  else
    report "no inline extraction" "no inline extraction" "${workflow}"
  fi
done

if [[ "${failures}" -gt 0 ]]; then
  echo "${failures} check(s) failed"
  exit 1
fi
echo "All KMS allowlist checks passed"
