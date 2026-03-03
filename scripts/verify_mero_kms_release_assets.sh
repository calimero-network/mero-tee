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

echo "Inspecting mero-kms-phala release ${tag}..."
release_json="$(gh release view "${tag}" --json assets,tagName,targetCommitish 2>/dev/null || true)"
if [[ -z "${release_json}" ]]; then
  echo "Release '${tag}' not found"
  exit 1
fi

base_signed_assets=(
  "mero-kms-phala-checksums.txt"
  "mero-kms-phala-release-manifest.json"
)

for asset in "${base_signed_assets[@]}"; do
  for suffix in "" ".sig" ".pem"; do
    signed_asset="${asset}${suffix}"
    if ! jq -e --arg asset "${signed_asset}" '.assets | any(.name == $asset)' <<< "${release_json}" >/dev/null; then
      echo "Release is missing required asset: ${signed_asset}"
      exit 1
    fi

    gh release download "${tag}" --pattern "${signed_asset}" --dir "${tmp_dir}" >/dev/null
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
    gh release download "${tag}" --pattern "${archive_asset}" --dir "${tmp_dir}" >/dev/null
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
  (.verification.kms_attest_endpoint == "/attest")
' "${tmp_dir}/mero-kms-phala-release-manifest.json" >/dev/null

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

echo "Release ${tag} checksums, manifest, archive hashes, and Sigstore signatures verified."
