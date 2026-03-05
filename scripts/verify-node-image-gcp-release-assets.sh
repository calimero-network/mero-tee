#!/usr/bin/env bash
set -euo pipefail

tag="${1:-}"
if [[ -z "${tag}" ]]; then
  echo "Usage: $0 <X.Y.Z>"
  exit 1
fi

logical_tag="${tag}"
if [[ "${logical_tag}" == locked-image-v* ]]; then
  logical_tag="${logical_tag#locked-image-v}"
fi

required_commands=(jq cosign curl git awk)
for cmd in "${required_commands[@]}"; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "${cmd} is required"
    exit 1
  fi
done

has_gh="false"
if command -v gh >/dev/null 2>&1; then
  has_gh="true"
fi

resolve_repo() {
  if [[ -n "${COSIGN_REPOSITORY:-}" ]]; then
    printf "%s\n" "${COSIGN_REPOSITORY}"
    return
  fi

  if [[ -n "${GITHUB_REPOSITORY:-}" ]]; then
    printf "%s\n" "${GITHUB_REPOSITORY}"
    return
  fi

  if [[ "${has_gh}" == "true" ]]; then
    local gh_repo
    gh_repo="$(gh repo view --json nameWithOwner --jq '.nameWithOwner' 2>/dev/null || true)"
    if [[ -n "${gh_repo}" ]]; then
      printf "%s\n" "${gh_repo}"
      return
    fi
  fi

  local origin_url
  origin_url="$(git remote get-url origin 2>/dev/null || true)"
  if [[ "${origin_url}" =~ ^https://github.com/([^/]+/[^/.]+)(\.git)?$ ]]; then
    printf "%s\n" "${BASH_REMATCH[1]}"
    return
  fi
  if [[ "${origin_url}" =~ ^git@github.com:([^/]+/[^/.]+)(\.git)?$ ]]; then
    printf "%s\n" "${BASH_REMATCH[1]}"
    return
  fi

  printf "%s\n" "calimero-network/mero-tee"
}

repo="$(resolve_repo)"
api_token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
api_headers=(-H "Accept: application/vnd.github+json")
if [[ -n "${api_token}" ]]; then
  api_headers+=(-H "Authorization: Bearer ${api_token}")
fi

base_signed_assets=(
  "mrtd-debug.json"
  "mrtd-debug-read-only.json"
  "mrtd-locked-read-only.json"
  "published-mrtds.json"
  "merod-locked-image-policy.json"
  "release-provenance.json"
)

bundle_asset=""
sbom_asset=""
checksums_asset=""
signed_assets=()
required_assets=()

tmp_dir="$(mktemp -d)"
cleanup() { rm -rf "${tmp_dir}"; }
trap cleanup EXIT

fetch_release_json() {
  local release_tag="$1"
  if [[ "${has_gh}" == "true" ]]; then
    gh release view "${release_tag}" --repo "${repo}" --json tagName,targetCommitish,assets 2>/dev/null || true
    return
  fi

  curl -fsSL "${api_headers[@]}" \
    "https://api.github.com/repos/${repo}/releases/tags/${release_tag}" 2>/dev/null || true
}

select_release_asset() {
  local release_payload="$1"
  shift

  local candidate
  for candidate in "$@"; do
    if jq -e --arg asset "${candidate}" '.assets | any(.name == $asset)' <<< "${release_payload}" >/dev/null 2>&1; then
      printf "%s\n" "${candidate}"
      return 0
    fi
  done
  return 1
}

download_asset() {
  local release_tag="$1"
  local asset_name="$2"
  local output_dir="$3"
  for attempt in $(seq 1 5); do
    if [[ "${has_gh}" == "true" ]]; then
      if gh release download "${release_tag}" --repo "${repo}" --pattern "${asset_name}" --dir "${output_dir}" >/dev/null 2>&1; then
        return 0
      fi
    else
      local asset_url
      asset_url="$(
        jq -r --arg asset "${asset_name}" '
          .assets[] | select(.name == $asset) | .browser_download_url
        ' <<< "${release_json}" | awk 'NR==1'
      )"
      if [[ -n "${asset_url}" && "${asset_url}" != "null" ]]; then
        if curl -fsSL "${api_headers[@]}" -o "${output_dir}/${asset_name}" "${asset_url}" >/dev/null 2>&1; then
          return 0
        fi
      fi
    fi

    if [[ "${attempt}" -eq 5 ]]; then
      return 1
    fi
    sleep 3
  done
}

echo "Inspecting release ${tag}..."
echo "Repository: ${repo} (download mode: $([[ "${has_gh}" == "true" ]] && echo "gh" || echo "curl"))"
release_tag="${tag}"
release_tag_candidates=("${tag}")
if [[ "${tag}" != locked-image-v* ]]; then
  release_tag_candidates+=("locked-image-v${tag}")
fi
release_json=""
for attempt in $(seq 1 10); do
  release_json=""
  missing_asset=""
  for candidate_tag in "${release_tag_candidates[@]}"; do
    candidate_json="$(fetch_release_json "${candidate_tag}")"
    if [[ -z "${candidate_json}" ]]; then
      continue
    fi

    candidate_bundle_asset="$(select_release_asset "${candidate_json}" "merod-locked-image-attestation-bundle.tar.gz" "attestation-artifacts.tar.gz" || true)"
    candidate_sbom_asset="$(select_release_asset "${candidate_json}" "merod-locked-image-release-sbom.spdx.json" "locked-image-release-sbom.spdx.json" || true)"
    candidate_checksums_asset="$(select_release_asset "${candidate_json}" "merod-locked-image-checksums.txt" "locked-image-checksums.txt" || true)"

    if [[ -z "${candidate_bundle_asset}" || -z "${candidate_sbom_asset}" || -z "${candidate_checksums_asset}" ]]; then
      continue
    fi

    candidate_signed_assets=("${base_signed_assets[@]}" "${candidate_bundle_asset}" "${candidate_sbom_asset}" "${candidate_checksums_asset}")
    candidate_required_assets=("${candidate_signed_assets[@]}")
    for asset in "${candidate_signed_assets[@]}"; do
      candidate_required_assets+=("${asset}.sig")
      candidate_required_assets+=("${asset}.pem")
    done

    candidate_missing_asset=""
    for asset in "${candidate_required_assets[@]}"; do
      if ! jq -e --arg asset "${asset}" '.assets | any(.name == $asset)' <<< "${candidate_json}" >/dev/null; then
        candidate_missing_asset="${asset}"
        break
      fi
    done
    if [[ -n "${candidate_missing_asset}" ]]; then
      missing_asset="${candidate_missing_asset}"
      continue
    fi

    release_tag="${candidate_tag}"
    release_json="${candidate_json}"
    bundle_asset="${candidate_bundle_asset}"
    sbom_asset="${candidate_sbom_asset}"
    checksums_asset="${candidate_checksums_asset}"
    signed_assets=("${candidate_signed_assets[@]}")
    required_assets=("${candidate_required_assets[@]}")
    break
  done

  if [[ -n "${release_json}" ]]; then
    break
  fi

  if [[ "${attempt}" -eq 10 ]]; then
    echo "Release asset set did not stabilize in time. Last missing asset: ${missing_asset:-unknown}"
    exit 1
  fi
  sleep 6
done

echo "Resolved release tag for locked-image assets: ${release_tag}"
echo "Locked-image checksums asset: ${checksums_asset}"
echo "Locked-image SBOM asset: ${sbom_asset}"
echo "Locked-image attestation bundle asset: ${bundle_asset}"

for pattern in "${required_assets[@]}"; do
  if ! download_asset "${release_tag}" "${pattern}" "${tmp_dir}"; then
    echo "Failed to download required asset ${pattern}"
    exit 1
  fi
done

for required in \
  "mrtd-debug.json" \
  "mrtd-debug-read-only.json" \
  "mrtd-locked-read-only.json" \
  "published-mrtds.json" \
  "merod-locked-image-policy.json" \
  "release-provenance.json" \
  "${bundle_asset}" \
  "${sbom_asset}"; do
  if ! awk -v req="${required}" '
    {
      # Handle optional CRLF artifacts safely when reading from downloaded assets.
      gsub(/\r$/, "", $2)
      if ($2 == req) {
        found = 1
      }
    }
    END { exit(found ? 0 : 1) }
  ' "${tmp_dir}/${checksums_asset}" >/dev/null 2>&1; then
    echo "Checksums file missing entry for ${required}"
    exit 1
  fi
done

jq -e --arg tag "${logical_tag}" '
  .tag == $tag and
  (.profiles.debug.mrtd | type == "string" and test("^[A-Fa-f0-9]{96}$")) and
  (.profiles["debug-read-only"].mrtd | type == "string" and test("^[A-Fa-f0-9]{96}$")) and
  (.profiles["locked-read-only"].mrtd | type == "string" and test("^[A-Fa-f0-9]{96}$"))
' "${tmp_dir}/published-mrtds.json" >/dev/null

jq -e --arg tag "${logical_tag}" '
  .schema_version == 1 and
  .tag == $tag and
  (.profiles.debug.allowed_mrtd | type == "array" and length > 0) and
  (.profiles.debug.allowed_rtmr0 | type == "array") and
  (.profiles.debug.allowed_rtmr1 | type == "array") and
  (.profiles.debug.allowed_rtmr2 | type == "array") and
  (.profiles.debug.allowed_rtmr3 | type == "array") and
  (.profiles["debug-read-only"].allowed_mrtd | type == "array" and length > 0) and
  (.profiles["debug-read-only"].allowed_rtmr0 | type == "array") and
  (.profiles["debug-read-only"].allowed_rtmr1 | type == "array") and
  (.profiles["debug-read-only"].allowed_rtmr2 | type == "array") and
  (.profiles["debug-read-only"].allowed_rtmr3 | type == "array") and
  (.profiles["locked-read-only"].allowed_mrtd | type == "array" and length > 0) and
  (.profiles["locked-read-only"].allowed_rtmr0 | type == "array") and
  (.profiles["locked-read-only"].allowed_rtmr1 | type == "array") and
  (.profiles["locked-read-only"].allowed_rtmr2 | type == "array") and
  (.profiles["locked-read-only"].allowed_rtmr3 | type == "array")
' "${tmp_dir}/merod-locked-image-policy.json" >/dev/null

jq -e --arg tag "${logical_tag}" '
  .tag == $tag and
  (.commit_sha | type == "string" and length > 0) and
  (.profiles.debug.image.name | type == "string" and length > 0) and
  (.profiles["debug-read-only"].image.name | type == "string" and length > 0) and
  (.profiles["locked-read-only"].image.name | type == "string" and length > 0) and
  (.profiles.debug.external_verification.status == "performed") and
  (.profiles["debug-read-only"].external_verification.status == "performed") and
  (.profiles["locked-read-only"].external_verification.status == "performed") and
  (.profiles.debug.external_verification.mrtd | type == "string" and test("^[A-Fa-f0-9]{96}$")) and
  (.profiles["debug-read-only"].external_verification.mrtd | type == "string" and test("^[A-Fa-f0-9]{96}$")) and
  (.profiles["locked-read-only"].external_verification.mrtd | type == "string" and test("^[A-Fa-f0-9]{96}$")) and
  (.mrtds.profiles.debug.mrtd == .profiles.debug.external_verification.mrtd) and
  (.mrtds.profiles["debug-read-only"].mrtd == .profiles["debug-read-only"].external_verification.mrtd) and
  (.mrtds.profiles["locked-read-only"].mrtd == .profiles["locked-read-only"].external_verification.mrtd) and
  (.measurement_policy.tag == $tag)
' "${tmp_dir}/release-provenance.json" >/dev/null

cert_identity_regex="${COSIGN_CERTIFICATE_IDENTITY_REGEXP:-^https://github.com/${repo}/.github/workflows/release-node-image-gcp.yaml@refs/heads/master$}"
cert_oidc_issuer="${COSIGN_CERTIFICATE_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

for asset in "${signed_assets[@]}"; do
  cosign verify-blob \
    --certificate "${tmp_dir}/${asset}.pem" \
    --signature "${tmp_dir}/${asset}.sig" \
    --certificate-identity-regexp "${cert_identity_regex}" \
    --certificate-oidc-issuer "${cert_oidc_issuer}" \
    "${tmp_dir}/${asset}" >/dev/null
done

echo "Release ${logical_tag} asset set, provenance checks, and Sigstore signature verification passed."
