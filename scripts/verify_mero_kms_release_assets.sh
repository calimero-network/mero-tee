#!/usr/bin/env bash
set -euo pipefail

tag="${1:-}"
if [[ -z "${tag}" ]]; then
  echo "Usage: $0 <X.Y.Z>"
  exit 1
fi

required_commands=(gh jq cosign sha256sum awk basename)
for cmd in "${required_commands[@]}"; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "${cmd} is required"
    exit 1
  fi
done

tmp_dir="$(mktemp -d)"
cleanup() { rm -rf "${tmp_dir}"; }
trap cleanup EXIT

download_asset() {
  local release_tag="$1"
  local pattern="$2"
  local output_dir="$3"
  for attempt in $(seq 1 5); do
    if gh release download "${release_tag}" --pattern "${pattern}" --dir "${output_dir}" >/dev/null 2>&1; then
      return 0
    fi
    if [[ "${attempt}" -eq 5 ]]; then
      return 1
    fi
    sleep 3
  done
}

echo "Inspecting mero-kms-phala release ${tag}..."
base_signed_assets=(
  "mero-kms-phala-checksums.txt"
  "mero-kms-phala-release-manifest.json"
  "mero-kms-phala-attestation-policy.json"
)

release_json=""
for attempt in $(seq 1 10); do
  release_json="$(gh release view "${tag}" --json assets,tagName,targetCommitish 2>/dev/null || true)"
  if [[ -n "${release_json}" ]]; then
    missing_asset=""
    for asset in "${base_signed_assets[@]}"; do
      for suffix in "" ".sig" ".pem"; do
        signed_asset="${asset}${suffix}"
        if ! jq -e --arg asset "${signed_asset}" '.assets | any(.name == $asset)' <<< "${release_json}" >/dev/null; then
          missing_asset="${signed_asset}"
          break 2
        fi
      done
    done
    if [[ -z "${missing_asset}" ]]; then
      break
    fi
  fi

  if [[ "${attempt}" -eq 10 ]]; then
    if [[ -z "${release_json}" ]]; then
      echo "Release '${tag}' not found"
    else
      echo "Release asset set did not stabilize in time. Last missing asset: ${missing_asset:-unknown}"
    fi
    exit 1
  fi
  sleep 6
done

for asset in "${base_signed_assets[@]}"; do
  for suffix in "" ".sig" ".pem"; do
    signed_asset="${asset}${suffix}"
    if ! download_asset "${tag}" "${signed_asset}" "${tmp_dir}"; then
      echo "Failed to download required asset ${signed_asset}"
      exit 1
    fi
  done
done

normalized_checksums="${tmp_dir}/normalized-checksums.txt"
> "${normalized_checksums}"

while read -r checksum filepath; do
  if [[ -z "${checksum}" || -z "${filepath}" ]]; then
    continue
  fi
  filename="$(basename "${filepath}")"
  printf "%s  %s\n" "${checksum}" "${filename}" >> "${normalized_checksums}"
done < "${tmp_dir}/mero-kms-phala-checksums.txt"

if [[ ! -s "${normalized_checksums}" ]]; then
  echo "No checksum entries found in mero-kms-phala-checksums.txt"
  exit 1
fi

mapfile -t archives < <(awk '{print $2}' "${normalized_checksums}")
if [[ "${#archives[@]}" -eq 0 ]]; then
  echo "No archive files listed in checksums file"
  exit 1
fi

for archive in "${archives[@]}"; do
  for suffix in "" ".sig" ".pem"; do
    archive_asset="${archive}${suffix}"
    if ! jq -e --arg asset "${archive_asset}" '.assets | any(.name == $asset)' <<< "${release_json}" >/dev/null; then
      echo "Release is missing required archive asset: ${archive_asset}"
      exit 1
    fi
    if ! download_asset "${tag}" "${archive_asset}" "${tmp_dir}"; then
      echo "Failed to download required archive asset ${archive_asset}"
      exit 1
    fi
  done
done

(
  cd "${tmp_dir}"
  sha256sum -c "${normalized_checksums}"
)

jq -e --arg tag "${tag}" '
  .tag == $tag and
  (.commit_sha | type == "string" and length > 0) and
  (.binaries | type == "array" and length > 0) and
  (.container.image | type == "string" and length > 0) and
  (.container.digest | type == "string" and length > 0) and
  (.verification.kms_attest_endpoint == "/attest") and
  (.verification.attestation_policy_asset == "mero-kms-phala-attestation-policy.json")
' "${tmp_dir}/mero-kms-phala-release-manifest.json" >/dev/null

jq -e --arg tag "${tag}" '
  .schema_version == 1 and
  .tag == $tag and
  (.commit_sha | type == "string" and length > 0) and
  (.kms.provider == "mero-kms-phala") and
  (.kms.attest_endpoint == "/attest") and
  (.kms.default_binding_hex | type == "string" and test("^[A-Fa-f0-9]{64}$")) and
  (.kms.default_binding_b64 | type == "string" and length > 0) and
  (.policy.allowed_tcb_statuses | type == "array" and length > 0) and
  (.policy.allowed_mrtd | type == "array") and
  (.policy.allowed_rtmr0 | type == "array") and
  (.policy.allowed_rtmr1 | type == "array") and
  (.policy.allowed_rtmr2 | type == "array") and
  (.policy.allowed_rtmr3 | type == "array")
' "${tmp_dir}/mero-kms-phala-attestation-policy.json" >/dev/null

manifest_commit="$(jq -r '.commit_sha' "${tmp_dir}/mero-kms-phala-release-manifest.json")"
policy_commit="$(jq -r '.commit_sha' "${tmp_dir}/mero-kms-phala-attestation-policy.json")"
if [[ "${manifest_commit}" != "${policy_commit}" ]]; then
  echo "Manifest and policy commit mismatch"
  echo "  manifest: ${manifest_commit}"
  echo "  policy:   ${policy_commit}"
  exit 1
fi

while read -r checksum archive; do
  manifest_checksum="$(
    jq -r --arg archive "${archive}" \
      '.binaries[] | select(.file == $archive) | .sha256' \
      "${tmp_dir}/mero-kms-phala-release-manifest.json" | awk 'NR==1'
  )"

  if [[ -z "${manifest_checksum}" || "${manifest_checksum}" == "null" ]]; then
    echo "Release manifest missing binary checksum entry for ${archive}"
    exit 1
  fi

  if [[ "${manifest_checksum,,}" != "${checksum,,}" ]]; then
    echo "Checksum mismatch between manifest and checksums for ${archive}"
    echo "  checksums.txt: ${checksum}"
    echo "  manifest.json: ${manifest_checksum}"
    exit 1
  fi
done < "${normalized_checksums}"

repo="${COSIGN_REPOSITORY:-}"
if [[ -z "${repo}" ]]; then
  repo="$(gh repo view --json nameWithOwner --jq '.nameWithOwner')"
fi

cert_identity_regex="${COSIGN_CERTIFICATE_IDENTITY_REGEXP:-^https://github.com/${repo}/.github/workflows/release-mero-kms-phala.yaml@refs/heads/master$}"
cert_oidc_issuer="${COSIGN_CERTIFICATE_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

signed_assets=(
  "mero-kms-phala-checksums.txt"
  "mero-kms-phala-release-manifest.json"
  "mero-kms-phala-attestation-policy.json"
)
for archive in "${archives[@]}"; do
  signed_assets+=("${archive}")
done

for asset in "${signed_assets[@]}"; do
  cosign verify-blob \
    --certificate "${tmp_dir}/${asset}.pem" \
    --signature "${tmp_dir}/${asset}.sig" \
    --certificate-identity-regexp "${cert_identity_regex}" \
    --certificate-oidc-issuer "${cert_oidc_issuer}" \
    "${tmp_dir}/${asset}" >/dev/null
done

echo "Release ${tag} checksums, manifest, attestation policy, archive hashes, and Sigstore signatures verified."
