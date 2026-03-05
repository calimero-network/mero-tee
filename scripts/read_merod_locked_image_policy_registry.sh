#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/read_merod_locked_image_policy_registry.sh <release-tag> [policy-index]

Examples:
  scripts/read_merod_locked_image_policy_registry.sh 2.1.4
  scripts/read_merod_locked_image_policy_registry.sh 2.1.4 policies/index.json

Prints normalized JSON to stdout:
{
  "schema_version": 1,
  "release_tag": "...",
  "mapped_version": "...",
  "merod_release_tag": "...",
  "source_policy_path": "...",
  "profiles": {
    "debug": { ... },
    "debug-read-only": { ... },
    "locked-read-only": { ... }
  }
}
EOF
}

release_tag="${1:-}"
policy_index="${2:-policies/index.json}"

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

index_file="${policy_index}"
if [[ ! -f "${index_file}" ]]; then
  echo "Policy index file not found: ${index_file}"
  exit 1
fi

if ! jq -e '.schema_version == 1 and (.releases | type == "array")' "${index_file}" >/dev/null; then
  echo "Policy index has invalid schema: ${index_file}"
  exit 1
fi

release_entry_json="$(
  jq -c --arg tag "${release_tag}" '
    [.releases[] | select(.version == $tag or .merod_release_tag == $tag)] | first // empty
  ' "${index_file}"
)"

if [[ -z "${release_entry_json}" ]]; then
  echo "No merod locked-image policy mapping found for release tag ${release_tag} in ${index_file}"
  exit 1
fi

policy_rel_path="$(jq -r '.merod_policy_path // empty' <<< "${release_entry_json}")"
expected_policy_tag="$(jq -r '.merod_release_tag // .version // empty' <<< "${release_entry_json}")"
mapped_version="$(jq -r '.version // empty' <<< "${release_entry_json}")"

if [[ -z "${policy_rel_path}" ]]; then
  echo "Merod policy path is missing for release tag ${release_tag} in ${index_file}"
  exit 1
fi

if [[ -z "${expected_policy_tag}" ]]; then
  echo "Merod release tag mapping is missing for release tag ${release_tag} in ${index_file}"
  exit 1
fi

if [[ -z "${mapped_version}" ]]; then
  echo "Version mapping is missing for release tag ${release_tag} in ${index_file}"
  exit 1
fi

if [[ ! -f "${policy_rel_path}" ]]; then
  echo "Policy file listed in index does not exist: ${policy_rel_path}"
  exit 1
fi

declared_tag="$(jq -r '.release_tag // .tag // empty' "${policy_rel_path}")"
if [[ -n "${declared_tag}" && "${declared_tag}" != "${expected_policy_tag}" ]]; then
  echo "Policy file tag mismatch for ${policy_rel_path}: expected ${expected_policy_tag}, found ${declared_tag}"
  exit 1
fi

profiles_json="$(
  jq -c '
    if (.profiles | type) == "object" then
      .profiles
    else
      empty
    end
  ' "${policy_rel_path}"
)"

if [[ -z "${profiles_json}" ]]; then
  echo "Policy file ${policy_rel_path} does not contain .profiles object"
  exit 1
fi

if ! jq -e '
  .debug
  and .["debug-read-only"]
  and .["locked-read-only"]
  and (.debug.allowed_mrtd | type == "array" and length > 0)
  and (.debug.allowed_rtmr0 | type == "array")
  and (.debug.allowed_rtmr1 | type == "array")
  and (.debug.allowed_rtmr2 | type == "array")
  and (.debug.allowed_rtmr3 | type == "array")
  and (.["debug-read-only"].allowed_mrtd | type == "array" and length > 0)
  and (.["debug-read-only"].allowed_rtmr0 | type == "array")
  and (.["debug-read-only"].allowed_rtmr1 | type == "array")
  and (.["debug-read-only"].allowed_rtmr2 | type == "array")
  and (.["debug-read-only"].allowed_rtmr3 | type == "array")
  and (.["locked-read-only"].allowed_mrtd | type == "array" and length > 0)
  and (.["locked-read-only"].allowed_rtmr0 | type == "array")
  and (.["locked-read-only"].allowed_rtmr1 | type == "array")
  and (.["locked-read-only"].allowed_rtmr2 | type == "array")
  and (.["locked-read-only"].allowed_rtmr3 | type == "array")
' <<< "${profiles_json}" >/dev/null; then
  echo "Policy file ${policy_rel_path} failed structural validation"
  exit 1
fi

jq -n \
  --arg release_tag "${release_tag}" \
  --arg mapped_version "${mapped_version}" \
  --arg merod_release_tag "${expected_policy_tag}" \
  --arg source_policy_path "${policy_rel_path}" \
  --argjson profiles "${profiles_json}" \
  '{
    schema_version: 1,
    release_tag: $release_tag,
    mapped_version: $mapped_version,
    merod_release_tag: $merod_release_tag,
    source_policy_path: $source_policy_path,
    profiles: $profiles
  }'
