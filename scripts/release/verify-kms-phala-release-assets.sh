#!/usr/bin/env bash
set -euo pipefail

tag="${1:-}"
if [[ -z "${tag}" ]]; then
  echo "Usage: $0 <X.Y.Z>"
  exit 1
fi

logical_tag="${tag}"
if [[ "${logical_tag}" == mero-kms-v* ]]; then
  logical_tag="${logical_tag#mero-kms-v}"
fi

required_commands=(jq cosign sha256sum awk basename curl git)
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

tmp_dir="$(mktemp -d)"
cleanup() { rm -rf "${tmp_dir}"; }
trap cleanup EXIT

fetch_release_json() {
  local release_tag="$1"
  if [[ "${has_gh}" == "true" ]]; then
    gh release view "${release_tag}" --repo "${repo}" --json assets,tagName,targetCommitish 2>/dev/null || true
    return
  fi

  curl -fsSL "${api_headers[@]}" \
    "https://api.github.com/repos/${repo}/releases/tags/${release_tag}" 2>/dev/null || true
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

echo "Inspecting mero-kms release ${tag}..."
echo "Repository: ${repo} (download mode: $([[ "${has_gh}" == "true" ]] && echo "gh" || echo "curl"))"
base_signed_assets=(
  "kms-phala-checksums.txt"
  "kms-phala-release-manifest.json"
  "kms-phala-attestation-policy.json"
  "kms-phala-compatibility-map.json"
  "kms-phala-container-metadata.json"
  "kms-phala-container-sbom.spdx.json"
  "kms-phala-binaries-sbom.spdx.json"
)
profile_policy_assets=(
  "kms-phala-attestation-policy.debug.json"
  "kms-phala-attestation-policy.debug-read-only.json"
  "kms-phala-attestation-policy.locked-read-only.json"
)

release_tag="${tag}"
release_tag_candidates=("${tag}")
if [[ "${tag}" != mero-kms-v* ]]; then
  release_tag_candidates=("mero-kms-v${tag}" "${tag}")
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

    candidate_missing_asset=""
    for asset in "${base_signed_assets[@]}"; do
      for suffix in "" ".sig" ".pem"; do
        signed_asset="${asset}${suffix}"
        if ! jq -e --arg asset "${signed_asset}" '.assets | any(.name == $asset)' <<< "${candidate_json}" >/dev/null; then
          candidate_missing_asset="${signed_asset}"
          break 2
        fi
      done
    done

    if [[ -n "${candidate_missing_asset}" ]]; then
      missing_asset="${candidate_missing_asset}"
      continue
    fi

    release_tag="${candidate_tag}"
    release_json="${candidate_json}"
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

echo "Resolved release tag for mero-kms assets: ${release_tag}"

has_profile_policy_assets="false"
for asset in "${profile_policy_assets[@]}"; do
  if jq -e --arg asset "${asset}" '.assets | any(.name == $asset)' <<< "${release_json}" >/dev/null; then
    has_profile_policy_assets="true"
    break
  fi
done

if [[ "${has_profile_policy_assets}" == "true" ]]; then
  for asset in "${profile_policy_assets[@]}"; do
    for suffix in "" ".sig" ".pem"; do
      profile_asset="${asset}${suffix}"
      if ! jq -e --arg asset "${profile_asset}" '.assets | any(.name == $asset)' <<< "${release_json}" >/dev/null; then
        echo "Release is missing required profile policy asset: ${profile_asset}"
        exit 1
      fi
      if ! download_asset "${release_tag}" "${profile_asset}" "${tmp_dir}"; then
        echo "Failed to download required profile policy asset ${profile_asset}"
        exit 1
      fi
    done
  done
fi

for asset in "${base_signed_assets[@]}"; do
  for suffix in "" ".sig" ".pem"; do
    signed_asset="${asset}${suffix}"
    if ! download_asset "${release_tag}" "${signed_asset}" "${tmp_dir}"; then
      echo "Failed to download required asset ${signed_asset}"
      exit 1
    fi
  done
done

normalized_checksums="${tmp_dir}/normalized-checksums.txt"
: > "${normalized_checksums}"

while read -r checksum filepath; do
  if [[ -z "${checksum}" || -z "${filepath}" ]]; then
    continue
  fi
  filename="$(basename "${filepath}")"
  printf "%s  %s\n" "${checksum}" "${filename}" >> "${normalized_checksums}"
done < "${tmp_dir}/kms-phala-checksums.txt"

if [[ ! -s "${normalized_checksums}" ]]; then
  echo "No checksum entries found in kms-phala-checksums.txt"
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
    if ! download_asset "${release_tag}" "${archive_asset}" "${tmp_dir}"; then
      echo "Failed to download required archive asset ${archive_asset}"
      exit 1
    fi
  done
done

(
  cd "${tmp_dir}"
  sha256sum -c "${normalized_checksums}"
)

jq -e --arg tag "${logical_tag}" '
  .tag == $tag and
  (.commit_sha | type == "string" and length > 0) and
  (.binaries | type == "array" and length > 0) and
  (.container.image | type == "string" and length > 0) and
  (.container.digest | type == "string" and length > 0) and
  (.verification.kms_attest_endpoint == "/attest") and
  (.verification.attestation_policy_asset == "kms-phala-attestation-policy.json") and
  (
    (.verification.policy_profile_assets == null) or
    (
      .verification.policy_profile_assets.debug == "kms-phala-attestation-policy.debug.json" and
      .verification.policy_profile_assets["debug-read-only"] == "kms-phala-attestation-policy.debug-read-only.json" and
      .verification.policy_profile_assets["locked-read-only"] == "kms-phala-attestation-policy.locked-read-only.json"
    )
  ) and
  (.verification.container_metadata_asset == "kms-phala-container-metadata.json")
' "${tmp_dir}/kms-phala-release-manifest.json" >/dev/null

jq -e --arg tag "${logical_tag}" '
  .schema_version == 1 and
  .tag == $tag and
  (.commit_sha | type == "string" and length > 0) and
  (.container.image | type == "string" and length > 0) and
  (.container.digest | type == "string" and test("^sha256:[A-Fa-f0-9]{64}$")) and
  (.container.tags | type == "array")
' "${tmp_dir}/kms-phala-container-metadata.json" >/dev/null

jq -e --arg tag "${logical_tag}" '
  .schema_version == 1 and
  .tag == $tag and
  (.compatibility.version == $tag) and
  (.compatibility.kms_tag == ("mero-kms-v" + $tag)) and
  (.compatibility.node_image_tag == ("mero-tee-v" + $tag)) and
  (.compatibility.profiles.debug.kms_policy_asset | type == "string" and length > 0) and
  (.compatibility.profiles["debug-read-only"].kms_policy_asset | type == "string" and length > 0) and
  (.compatibility.profiles["locked-read-only"].kms_policy_asset | type == "string" and length > 0) and
  (.compatibility.profiles.debug.kms_image_tag | type == "string" and length > 0) and
  (.compatibility.profiles["debug-read-only"].kms_image_tag | type == "string" and length > 0) and
  (.compatibility.profiles["locked-read-only"].kms_image_tag | type == "string" and length > 0) and
  (.compatibility.profiles.debug.node_profile == "debug") and
  (.compatibility.profiles["debug-read-only"].node_profile == "debug-read-only") and
  (.compatibility.profiles["locked-read-only"].node_profile == "locked-read-only")
' "${tmp_dir}/kms-phala-compatibility-map.json" >/dev/null

jq -e --arg tag "${logical_tag}" '
  .schema_version == 1 and
  .tag == $tag and
  (.commit_sha | type == "string" and length > 0) and
  (.kms.provider == "mero-kms-phala") and
  (.kms.attest_endpoint == "/attest") and
  (.kms.default_binding_hex | type == "string" and test("^[A-Fa-f0-9]{64}$")) and
  (.kms.default_binding_b64 | type == "string" and length > 0) and
  ((.policy.kms_allowed_tcb_statuses // .policy.allowed_tcb_statuses) | type == "array" and length > 0) and
  (((.policy.kms_allowed_mrtd // .policy.allowed_mrtd) | type == "array" and length > 0)) and
  (((.policy.kms_allowed_rtmr0 // .policy.allowed_rtmr0) | type == "array" and length > 0)) and
  (((.policy.kms_allowed_rtmr1 // .policy.allowed_rtmr1) | type == "array" and length > 0)) and
  (((.policy.kms_allowed_rtmr2 // .policy.allowed_rtmr2) | type == "array" and length > 0)) and
  (((.policy.kms_allowed_rtmr3 // .policy.allowed_rtmr3) | type == "array" and length > 0))
' "${tmp_dir}/kms-phala-attestation-policy.json" >/dev/null

if [[ "${has_profile_policy_assets}" == "true" ]]; then
  for profile in debug debug-read-only locked-read-only; do
    profile_file="${tmp_dir}/kms-phala-attestation-policy.${profile}.json"
    jq -e --arg tag "${logical_tag}" --arg profile "${profile}" '
      .schema_version == 1 and
      .tag == $tag and
      (.commit_sha | type == "string" and length > 0) and
      ((.profile // "locked-read-only") == $profile) and
      (.kms.provider == "mero-kms-phala") and
      (.kms.attest_endpoint == "/attest") and
      (.kms.default_binding_hex | type == "string" and test("^[A-Fa-f0-9]{64}$")) and
      (.kms.default_binding_b64 | type == "string" and length > 0) and
      ((.policy.kms_allowed_tcb_statuses // .policy.allowed_tcb_statuses) | type == "array" and length > 0) and
      (((.policy.kms_allowed_mrtd // .policy.allowed_mrtd) | type == "array" and length > 0)) and
      (((.policy.kms_allowed_rtmr0 // .policy.allowed_rtmr0) | type == "array" and length > 0)) and
      (((.policy.kms_allowed_rtmr1 // .policy.allowed_rtmr1) | type == "array" and length > 0)) and
      (((.policy.kms_allowed_rtmr2 // .policy.allowed_rtmr2) | type == "array" and length > 0)) and
      (((.policy.kms_allowed_rtmr3 // .policy.allowed_rtmr3) | type == "array" and length > 0)) and
      (((.policy.node_allowed_mrtd // .policy.allowed_mrtd) | type == "array" and length > 0)) and
      (((.policy.node_allowed_rtmr0 // .policy.allowed_rtmr0) | type == "array" and length > 0)) and
      (((.policy.node_allowed_rtmr1 // .policy.allowed_rtmr1) | type == "array" and length > 0)) and
      (((.policy.node_allowed_rtmr2 // .policy.allowed_rtmr2) | type == "array" and length > 0)) and
      (((.policy.node_allowed_rtmr3 // .policy.allowed_rtmr3) | type == "array" and length > 0))
    ' "${profile_file}" >/dev/null
  done
fi

manifest_commit="$(jq -r '.commit_sha' "${tmp_dir}/kms-phala-release-manifest.json")"
policy_commit="$(jq -r '.commit_sha' "${tmp_dir}/kms-phala-attestation-policy.json")"
container_metadata_commit="$(jq -r '.commit_sha' "${tmp_dir}/kms-phala-container-metadata.json")"
if [[ "${manifest_commit}" != "${policy_commit}" ]]; then
  echo "Manifest and policy commit mismatch"
  echo "  manifest: ${manifest_commit}"
  echo "  policy:   ${policy_commit}"
  exit 1
fi
if [[ "${has_profile_policy_assets}" == "true" ]]; then
  for profile in debug debug-read-only locked-read-only; do
    profile_commit="$(jq -r '.commit_sha' "${tmp_dir}/kms-phala-attestation-policy.${profile}.json")"
    if [[ "${manifest_commit}" != "${profile_commit}" ]]; then
      echo "Manifest and ${profile} policy commit mismatch"
      echo "  manifest: ${manifest_commit}"
      echo "  policy:   ${profile_commit}"
      exit 1
    fi
  done
fi
if [[ "${manifest_commit}" != "${container_metadata_commit}" ]]; then
  echo "Manifest and container metadata commit mismatch"
  echo "  manifest:  ${manifest_commit}"
  echo "  metadata:  ${container_metadata_commit}"
  exit 1
fi

manifest_container_digest="$(jq -r '.container.digest' "${tmp_dir}/kms-phala-release-manifest.json")"
metadata_container_digest="$(jq -r '.container.digest' "${tmp_dir}/kms-phala-container-metadata.json")"
if [[ "${manifest_container_digest}" != "${metadata_container_digest}" ]]; then
  echo "Manifest and container metadata digest mismatch"
  echo "  manifest: ${manifest_container_digest}"
  echo "  metadata: ${metadata_container_digest}"
  exit 1
fi

while read -r checksum archive; do
  manifest_checksum="$(
    jq -r --arg archive "${archive}" \
      '.binaries[] | select(.file == $archive) | .sha256' \
      "${tmp_dir}/kms-phala-release-manifest.json" | awk 'NR==1'
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

cert_identity_regex="${COSIGN_CERTIFICATE_IDENTITY_REGEXP:-^https://github.com/${repo}/.github/workflows/release-kms-phala.yaml@refs/heads/master$}"
cert_oidc_issuer="${COSIGN_CERTIFICATE_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

signed_assets=(
  "kms-phala-checksums.txt"
  "kms-phala-release-manifest.json"
  "kms-phala-attestation-policy.json"
  "kms-phala-container-metadata.json"
  "kms-phala-container-sbom.spdx.json"
  "kms-phala-binaries-sbom.spdx.json"
)
for archive in "${archives[@]}"; do
  signed_assets+=("${archive}")
done
if [[ "${has_profile_policy_assets}" == "true" ]]; then
  for asset in "${profile_policy_assets[@]}"; do
    signed_assets+=("${asset}")
  done
fi

for asset in "${signed_assets[@]}"; do
  cosign verify-blob \
    --certificate "${tmp_dir}/${asset}.pem" \
    --signature "${tmp_dir}/${asset}.sig" \
    --certificate-identity-regexp "${cert_identity_regex}" \
    --certificate-oidc-issuer "${cert_oidc_issuer}" \
    "${tmp_dir}/${asset}" >/dev/null
done

echo "Release ${logical_tag} checksums, manifest, attestation policy, container metadata, archive hashes, and Sigstore signatures verified."
