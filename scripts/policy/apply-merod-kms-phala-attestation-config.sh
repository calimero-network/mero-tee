#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/policy/apply-merod-kms-phala-attestation-config.sh [--dry-run] <release-tag> <kms-url> <merod-home> [node-name]

Examples:
  scripts/policy/apply-merod-kms-phala-attestation-config.sh 1.2.3 https://kms-green.example.com/ /data default
  scripts/policy/apply-merod-kms-phala-attestation-config.sh --dry-run 1.2.3 http://127.0.0.1:8080/ ~/.calimero default
EOF
}

dry_run="false"
if [[ "${1:-}" == "--dry-run" ]]; then
  dry_run="true"
  shift
fi

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

release_tag="${1:-}"
kms_url="${2:-}"
merod_home="${3:-}"
node_name="${4:-default}"

if [[ -z "${release_tag}" || -z "${kms_url}" || -z "${merod_home}" ]]; then
  usage
  exit 1
fi

required_commands=(gh jq cosign merod mktemp)
for cmd in "${required_commands[@]}"; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "${cmd} is required"
    exit 1
  fi
done

download_asset() {
  local tag="$1"
  local pattern="$2"
  local out_dir="$3"
  for attempt in $(seq 1 5); do
    if gh release download "${tag}" --pattern "${pattern}" --dir "${out_dir}" >/dev/null 2>&1; then
      return 0
    fi
    if [[ "${attempt}" -eq 5 ]]; then
      return 1
    fi
    sleep 2
  done
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"${script_dir}/../release/verify-kms-phala-release-assets.sh" "${release_tag}" >/dev/null

tmp_dir="$(mktemp -d)"
cleanup() { rm -rf "${tmp_dir}"; }
trap cleanup EXIT

for pattern in \
  "kms-phala-attestation-policy.json" \
  "kms-phala-attestation-policy.json.sig" \
  "kms-phala-attestation-policy.json.pem"; do
  if ! download_asset "${release_tag}" "${pattern}" "${tmp_dir}"; then
    echo "Failed to download required asset ${pattern}"
    exit 1
  fi
done

repo="${COSIGN_REPOSITORY:-}"
if [[ -z "${repo}" ]]; then
  repo="$(gh repo view --json nameWithOwner --jq '.nameWithOwner')"
fi

cert_identity_regex="${COSIGN_CERTIFICATE_IDENTITY_REGEXP:-^https://github.com/${repo}/.github/workflows/release-kms-phala.yaml@refs/heads/master$}"
cert_oidc_issuer="${COSIGN_CERTIFICATE_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

policy_file="${tmp_dir}/kms-phala-attestation-policy.json"
cosign verify-blob \
  --certificate "${policy_file}.pem" \
  --signature "${policy_file}.sig" \
  --certificate-identity-regexp "${cert_identity_regex}" \
  --certificate-oidc-issuer "${cert_oidc_issuer}" \
  "${policy_file}" >/dev/null

jq -e --arg tag "${release_tag}" '
  .schema_version == 1 and
  .tag == $tag and
  (.policy.allowed_tcb_statuses | type == "array" and length > 0) and
  (.policy.allowed_mrtd | type == "array") and
  (.policy.allowed_rtmr0 | type == "array") and
  (.policy.allowed_rtmr1 | type == "array") and
  (.policy.allowed_rtmr2 | type == "array") and
  (.policy.allowed_rtmr3 | type == "array") and
  (.kms.attest_endpoint == "/attest") and
  (.kms.default_binding_b64 | type == "string" and length > 0)
' "${policy_file}" >/dev/null

allowed_tcb_statuses="$(jq -c '.policy.allowed_tcb_statuses' "${policy_file}")"
allowed_mrtd="$(jq -c '.policy.allowed_mrtd' "${policy_file}")"
allowed_rtmr0="$(jq -c '.policy.allowed_rtmr0' "${policy_file}")"
allowed_rtmr1="$(jq -c '.policy.allowed_rtmr1' "${policy_file}")"
allowed_rtmr2="$(jq -c '.policy.allowed_rtmr2' "${policy_file}")"
allowed_rtmr3="$(jq -c '.policy.allowed_rtmr3' "${policy_file}")"
binding_b64="$(jq -r '.kms.default_binding_b64' "${policy_file}")"
commit_sha="$(jq -r '.commit_sha' "${policy_file}")"

kms_url_json="$(jq -Rn --arg value "${kms_url}" '$value')"
binding_b64_json="$(jq -Rn --arg value "${binding_b64}" '$value')"

updates=(
  "tee.kms.phala.url=${kms_url_json}"
  "tee.kms.phala.attestation.enabled=true"
  "tee.kms.phala.attestation.accept_mock=false"
  "tee.kms.phala.attestation.allowed_tcb_statuses=${allowed_tcb_statuses}"
  "tee.kms.phala.attestation.allowed_mrtd=${allowed_mrtd}"
  "tee.kms.phala.attestation.allowed_rtmr0=${allowed_rtmr0}"
  "tee.kms.phala.attestation.allowed_rtmr1=${allowed_rtmr1}"
  "tee.kms.phala.attestation.allowed_rtmr2=${allowed_rtmr2}"
  "tee.kms.phala.attestation.allowed_rtmr3=${allowed_rtmr3}"
  "tee.kms.phala.attestation.binding_b64=${binding_b64_json}"
)

echo "Applying release-pinned KMS attestation config"
echo "  tag: ${release_tag}"
echo "  commit: ${commit_sha}"
echo "  home: ${merod_home}"
echo "  node: ${node_name}"

for update in "${updates[@]}"; do
  if [[ "${dry_run}" == "true" ]]; then
    printf "merod --home %q --node %q config %q\n" "${merod_home}" "${node_name}" "${update}"
  else
    merod --home "${merod_home}" --node "${node_name}" config "${update}"
  fi
done

if [[ "${dry_run}" == "true" ]]; then
  echo "Dry-run complete. No changes were written."
else
  echo "Successfully updated merod config with signed policy from release ${release_tag}."
fi
