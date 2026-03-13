#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/policy/generate-merod-kms-phala-attestation-config.sh [--profile <debug|debug-read-only|locked-read-only>] <release-tag> <kms-url> [output-file]

Examples:
  scripts/policy/generate-merod-kms-phala-attestation-config.sh 1.2.3 http://kms.internal:8080/
  scripts/policy/generate-merod-kms-phala-attestation-config.sh --profile debug 1.2.3 https://kms.example.com/ ./tee-kms.toml
EOF
}

profile="locked-read-only"
positional=()
while [[ $# -gt 0 ]]; do
  case "${1}" in
    --profile)
      profile="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      positional+=("${1}")
      shift
      ;;
  esac
done
set -- "${positional[@]}"

case "${profile}" in
  debug|debug-read-only|locked-read-only) ;;
  *)
    echo "Unsupported --profile '${profile}'. Allowed: debug, debug-read-only, locked-read-only"
    exit 1
    ;;
esac

tag="${1:-}"
kms_url="${2:-}"
output_file="${3:-}"

if [[ -z "${tag}" || -z "${kms_url}" ]]; then
  usage
  exit 1
fi

required_commands=(gh jq cosign dirname mktemp)
for cmd in "${required_commands[@]}"; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "${cmd} is required"
    exit 1
  fi
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"${script_dir}/../release/verify-kms-phala-release-assets.sh" "${tag}" >/dev/null

resolved_tag="${tag}"
if ! gh release view "${resolved_tag}" >/dev/null 2>&1 && [[ "${tag}" != mero-kms-v* ]]; then
  resolved_tag="mero-kms-v${tag}"
fi
logical_tag="${tag#mero-kms-v}"

tmp_dir="$(mktemp -d)"
cleanup() { rm -rf "${tmp_dir}"; }
trap cleanup EXIT

policy_asset="kms-phala-attestation-policy.${profile}.json"
downloaded_profile_asset="false"
for attempt in $(seq 1 5); do
  if gh release download "${resolved_tag}" --pattern "${policy_asset}" --dir "${tmp_dir}" >/dev/null 2>&1; then
    downloaded_profile_asset="true"
    break
  fi
  sleep 2
done
if [[ "${downloaded_profile_asset}" != "true" ]]; then
  if [[ "${profile}" == "locked-read-only" ]]; then
    policy_asset="kms-phala-attestation-policy.json"
    if ! gh release download "${resolved_tag}" --pattern "${policy_asset}" --dir "${tmp_dir}" >/dev/null 2>&1; then
      echo "Failed to download required asset ${policy_asset}"
      exit 1
    fi
  else
    echo "Failed to download required asset kms-phala-attestation-policy.${profile}.json"
    exit 1
  fi
fi

for pattern in "${policy_asset}.sig" "${policy_asset}.pem"; do
  for attempt in $(seq 1 5); do
    if gh release download "${resolved_tag}" --pattern "${pattern}" --dir "${tmp_dir}" >/dev/null 2>&1; then
      break
    fi
    if [[ "${attempt}" -eq 5 ]]; then
      echo "Failed to download required asset ${pattern}"
      exit 1
    fi
    sleep 2
  done
done

repo="${COSIGN_REPOSITORY:-}"
if [[ -z "${repo}" ]]; then
  repo="$(gh repo view --json nameWithOwner --jq '.nameWithOwner')"
fi

cert_identity_regex="${COSIGN_CERTIFICATE_IDENTITY_REGEXP:-^https://github.com/${repo}/.github/workflows/release-kms-phala.yaml@refs/heads/master$}"
cert_oidc_issuer="${COSIGN_CERTIFICATE_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

policy_file="${tmp_dir}/${policy_asset}"
cosign verify-blob \
  --certificate "${policy_file}.pem" \
  --signature "${policy_file}.sig" \
  --certificate-identity-regexp "${cert_identity_regex}" \
  --certificate-oidc-issuer "${cert_oidc_issuer}" \
  "${policy_file}" >/dev/null

jq -e --arg tag "${logical_tag}" '
  .schema_version == 1 and
  .tag == $tag and
  ((.policy.kms_allowed_tcb_statuses // .policy.allowed_tcb_statuses) | type == "array" and length > 0) and
  (((.policy.kms_allowed_mrtd // .policy.allowed_mrtd) | type == "array" and length > 0)) and
  (((.policy.kms_allowed_rtmr0 // .policy.allowed_rtmr0) | type == "array" and length > 0)) and
  (((.policy.kms_allowed_rtmr1 // .policy.allowed_rtmr1) | type == "array" and length > 0)) and
  (((.policy.kms_allowed_rtmr2 // .policy.allowed_rtmr2) | type == "array" and length > 0)) and
  (((.policy.kms_allowed_rtmr3 // .policy.allowed_rtmr3) | type == "array" and length > 0)) and
  (.kms.attest_endpoint == "/attest") and
  (.kms.default_binding_b64 | type == "string" and length > 0)
' "${policy_file}" >/dev/null

# Merod verifies the KMS; use kms_allowed_* (fallback to allowed_* for legacy)
allowed_tcb_statuses="$(jq -c '.policy.kms_allowed_tcb_statuses // .policy.allowed_tcb_statuses' "${policy_file}")"
allowed_mrtd="$(jq -c '.policy.kms_allowed_mrtd // .policy.allowed_mrtd' "${policy_file}")"
allowed_rtmr0="$(jq -c '.policy.kms_allowed_rtmr0 // .policy.allowed_rtmr0' "${policy_file}")"
allowed_rtmr1="$(jq -c '.policy.kms_allowed_rtmr1 // .policy.allowed_rtmr1' "${policy_file}")"
allowed_rtmr2="$(jq -c '.policy.kms_allowed_rtmr2 // .policy.allowed_rtmr2' "${policy_file}")"
allowed_rtmr3="$(jq -c '.policy.kms_allowed_rtmr3 // .policy.allowed_rtmr3' "${policy_file}")"
binding_b64="$(jq -r '.kms.default_binding_b64' "${policy_file}")"
commit_sha="$(jq -r '.commit_sha' "${policy_file}")"

snippet="$(
  cat <<EOF
# Generated from mero-tee release ${tag} (commit ${commit_sha}, profile ${profile})
# Do not auto-follow latest: pin this to a reviewed release tag.

[tee]
[tee.kms.phala]
url = "${kms_url}"

[tee.kms.phala.attestation]
enabled = true
accept_mock = false
allowed_tcb_statuses = ${allowed_tcb_statuses}
allowed_mrtd = ${allowed_mrtd}
allowed_rtmr0 = ${allowed_rtmr0}
allowed_rtmr1 = ${allowed_rtmr1}
allowed_rtmr2 = ${allowed_rtmr2}
allowed_rtmr3 = ${allowed_rtmr3}
binding_b64 = "${binding_b64}"
EOF
)"

if [[ -n "${output_file}" ]]; then
  printf "%s\n" "${snippet}" > "${output_file}"
  echo "Wrote merod TEE KMS attestation config to ${output_file}"
else
  printf "%s\n" "${snippet}"
fi
