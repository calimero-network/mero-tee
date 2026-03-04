#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/read_mero_kms_policy_registry.sh <release-tag> [policy-root]

Examples:
  scripts/read_mero_kms_policy_registry.sh 2.1.3
  scripts/read_mero_kms_policy_registry.sh 2.1.3 policies/mero-kms-phala

Prints normalized JSON to stdout:
{
  "schema_version": 1,
  "release_tag": "...",
  "source_policy_path": "...",
  "policy": {
    "allowed_tcb_statuses": [...],
    "allowed_mrtd": [...],
    "allowed_rtmr0": [...],
    "allowed_rtmr1": [...],
    "allowed_rtmr2": [...],
    "allowed_rtmr3": [...]
  }
}
EOF
}

release_tag="${1:-}"
policy_root="${2:-policies/mero-kms-phala}"

if [[ "${release_tag}" == "-h" || "${release_tag}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "${release_tag}" ]]; then
  usage
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required"
  exit 1
fi

index_file="${policy_root}/index.json"
if [[ ! -f "${index_file}" ]]; then
  echo "Policy index file not found: ${index_file}"
  exit 1
fi

if ! jq -e '.schema_version == 1 and (.policies | type == "array")' "${index_file}" >/dev/null; then
  echo "Policy index has invalid schema: ${index_file}"
  exit 1
fi

policy_rel_path="$(
  jq -r --arg tag "${release_tag}" '
    [.policies[] | select(.release_tag == $tag) | .path] | first // empty
  ' "${index_file}"
)"

if [[ -z "${policy_rel_path}" ]]; then
  echo "No policy entry found for release tag ${release_tag} in ${index_file}"
  exit 1
fi

if [[ ! -f "${policy_rel_path}" ]]; then
  echo "Policy file listed in index does not exist: ${policy_rel_path}"
  exit 1
fi

declared_tag="$(jq -r '.release_tag // .tag // empty' "${policy_rel_path}")"
if [[ -n "${declared_tag}" && "${declared_tag}" != "${release_tag}" ]]; then
  echo "Policy file tag mismatch for ${policy_rel_path}: expected ${release_tag}, found ${declared_tag}"
  exit 1
fi

policy_json="$(
  jq -c '
    if (.policy | type) == "object" then
      .policy
    elif (.candidate_policy | type) == "object" then
      .candidate_policy
    else
      empty
    end
  ' "${policy_rel_path}"
)"

if [[ -z "${policy_json}" ]]; then
  echo "Policy file ${policy_rel_path} does not contain .policy or .candidate_policy object"
  exit 1
fi

if ! jq -e '
  (.allowed_tcb_statuses | type == "array" and length > 0) and
  (.allowed_mrtd | type == "array") and
  (.allowed_rtmr0 | type == "array") and
  (.allowed_rtmr1 | type == "array") and
  (.allowed_rtmr2 | type == "array") and
  (.allowed_rtmr3 | type == "array")
' <<< "${policy_json}" >/dev/null; then
  echo "Policy file ${policy_rel_path} failed structural validation"
  exit 1
fi

jq -n \
  --arg release_tag "${release_tag}" \
  --arg source_policy_path "${policy_rel_path}" \
  --argjson policy "${policy_json}" \
  '{
    schema_version: 1,
    release_tag: $release_tag,
    source_policy_path: $source_policy_path,
    policy: $policy
  }'
