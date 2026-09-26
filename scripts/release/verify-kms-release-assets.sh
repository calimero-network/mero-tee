#!/usr/bin/env bash
set -euo pipefail

# Verify a mero-kms release (published by release-kms.yaml): every trust asset
# is present and Sigstore-signed by the release workflow, the binary archives
# match kms-checksums.txt and the manifest, and the attestation policies have
# the shape merod parses (`[tee.kms.attestation]`), with profile-separated KMS
# measurements and role-separated KMS/node RTMR2/RTMR3.

tag="${1:-}"
if [[ -z "${tag}" ]]; then
  echo "Usage: $0 <X.Y.Z|mero-kms-vX.Y.Z>"
  exit 1
fi

logical_tag="${tag#mero-kms-v}"
release_tag="mero-kms-v${logical_tag}"

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
  if [[ "${has_gh}" == "true" ]]; then
    gh release view "${release_tag}" --repo "${repo}" --json assets,tagName,targetCommitish 2>/dev/null || true
    return
  fi
  curl -fsSL "${api_headers[@]}" \
    "https://api.github.com/repos/${repo}/releases/tags/${release_tag}" 2>/dev/null || true
}

download_asset() {
  local asset_name="$1"
  for attempt in $(seq 1 5); do
    if [[ "${has_gh}" == "true" ]]; then
      if gh release download "${release_tag}" --repo "${repo}" --pattern "${asset_name}" --dir "${tmp_dir}" >/dev/null 2>&1; then
        return 0
      fi
    else
      local asset_url
      asset_url="$(jq -r --arg asset "${asset_name}" \
        '.assets[] | select(.name == $asset) | .browser_download_url' <<< "${release_json}" | awk 'NR==1')"
      if [[ -n "${asset_url}" && "${asset_url}" != "null" ]] \
        && curl -fsSL "${api_headers[@]}" -o "${tmp_dir}/${asset_name}" "${asset_url}" >/dev/null 2>&1; then
        return 0
      fi
    fi
    if [[ "${attempt}" -eq 5 ]]; then
      return 1
    fi
    sleep 3
  done
}

profiles=(debug debug-read-only locked-read-only)
signed_json_assets=(
  "kms-checksums.txt"
  "kms-release-manifest.json"
  "kms-compatibility-map.json"
  "kms-binaries-sbom.spdx.json"
  "kms-rekor-index.json"
  "kms-trust-bundle.tar.gz"
  "kms-attestation-policy.json"
)
for profile in "${profiles[@]}"; do
  signed_json_assets+=("kms-attestation-policy.${profile}.json")
done

echo "Inspecting mero-kms release ${release_tag}..."
echo "Repository: ${repo} (download mode: $([[ "${has_gh}" == "true" ]] && echo "gh" || echo "curl"))"

release_json=""
missing_asset=""
for attempt in $(seq 1 10); do
  release_json="$(fetch_release_json)"
  missing_asset=""
  if [[ -n "${release_json}" ]]; then
    for asset in "${signed_json_assets[@]}"; do
      for suffix in "" ".sig" ".pem"; do
        if ! jq -e --arg asset "${asset}${suffix}" '.assets | any(.name == $asset)' <<< "${release_json}" >/dev/null; then
          missing_asset="${asset}${suffix}"
          break 2
        fi
      done
    done
    if [[ -z "${missing_asset}" ]]; then
      break
    fi
  fi
  if [[ "${attempt}" -eq 10 ]]; then
    echo "Release asset set did not stabilize in time. Last missing asset: ${missing_asset:-release ${release_tag} not found}"
    exit 1
  fi
  sleep 6
done

for asset in "${signed_json_assets[@]}"; do
  for suffix in "" ".sig" ".pem"; do
    if ! download_asset "${asset}${suffix}"; then
      echo "Failed to download required asset ${asset}${suffix}"
      exit 1
    fi
  done
done

mapfile -t archives < <(awk 'NF == 2 {print $2}' "${tmp_dir}/kms-checksums.txt")
if [[ "${#archives[@]}" -eq 0 ]]; then
  echo "No archive files listed in kms-checksums.txt"
  exit 1
fi
for archive in "${archives[@]}"; do
  for suffix in "" ".sig" ".pem"; do
    if ! download_asset "${archive}${suffix}"; then
      echo "Failed to download required archive asset ${archive}${suffix}"
      exit 1
    fi
  done
done

(
  cd "${tmp_dir}"
  sha256sum -c kms-checksums.txt
)

jq -e --arg tag "${logical_tag}" '
  .tag == $tag and
  (.commit_sha | type == "string" and length > 0) and
  (.binaries | type == "array" and length > 0) and
  ([.images.debug.name, .images["debug-read-only"].name, .images["locked-read-only"].name]
    | all(type == "string" and test("^merotee-kms-")) and (unique | length == 3)) and
  (.verification.kms_attest_endpoint == "/attest") and
  (.verification.attestation_policy_asset == "kms-attestation-policy.json") and
  (.verification.policy_profile_assets.debug == "kms-attestation-policy.debug.json") and
  (.verification.policy_profile_assets["debug-read-only"] == "kms-attestation-policy.debug-read-only.json") and
  (.verification.policy_profile_assets["locked-read-only"] == "kms-attestation-policy.locked-read-only.json") and
  (.verification.compatibility_map_asset == "kms-compatibility-map.json")
' "${tmp_dir}/kms-release-manifest.json" >/dev/null \
  || { echo "kms-release-manifest.json does not have the expected shape"; exit 1; }

jq -e --arg tag "${logical_tag}" '
  .schema_version == 1 and
  .tag == $tag and
  (.compatibility.version == $tag) and
  (.compatibility.kms_tag == ("mero-kms-v" + $tag)) and
  (.compatibility.node_image_tag == ("mero-tee-v" + $tag)) and
  (.compatibility.profiles | to_entries | length == 3) and
  all(.compatibility.profiles | to_entries[]; . as $e |
    $e.value.node_profile == $e.key and
    $e.value.kms_policy_asset == ("kms-attestation-policy." + $e.key + ".json") and
    ($e.value.kms_image | type == "string" and test("^merotee-kms-" + $e.key + "-[0-9]")) and
    ($e.value.kms_policy_sha256 | type == "string" and test("^[a-f0-9]{64}$")))
' "${tmp_dir}/kms-compatibility-map.json" >/dev/null \
  || { echo "kms-compatibility-map.json does not have the expected shape"; exit 1; }

expected_binding_hex="$(printf '%s' 'mero-kms-attest-v1' | sha256sum | awk '{print $1}')"

check_policy() {
  local file="$1"
  local profile="$2"
  jq -e --arg tag "${logical_tag}" --arg profile "${profile}" --arg binding "${expected_binding_hex}" '
    .schema_version == 1 and
    .tag == $tag and
    .role == "kms" and
    .profile == $profile and
    (.commit_sha | type == "string" and length > 0) and
    .kms.provider == "mero-kms" and
    .kms.attest_endpoint == "/attest" and
    .kms.default_binding_hex == $binding and
    (.kms.default_binding_b64 | type == "string" and length > 0) and
    .merod_config_path == "tee.kms.attestation" and
    (.policy | has("kms_allowed_event_payload") | not) and
    (.policy.kms_allowed_tcb_statuses | index("uptodate") != null) and
    (.policy.node_allowed_tcb_statuses | index("uptodate") != null) and
    (.policy as $p | all(["kms", "node"][] as $role | ["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"][] as $m
      | $p["\($role)_allowed_\($m)"]; type == "array" and length > 0))
  ' "${file}" >/dev/null || { echo "$(basename "${file}") does not have the expected shape"; exit 1; }
}

check_policy "${tmp_dir}/kms-attestation-policy.json" "locked-read-only"
if ! cmp -s "${tmp_dir}/kms-attestation-policy.json" "${tmp_dir}/kms-attestation-policy.locked-read-only.json"; then
  echo "kms-attestation-policy.json is not the locked-read-only policy"
  exit 1
fi

manifest_commit="$(jq -r '.commit_sha' "${tmp_dir}/kms-release-manifest.json")"
for profile in "${profiles[@]}"; do
  file="${tmp_dir}/kms-attestation-policy.${profile}.json"
  check_policy "${file}" "${profile}"
  if [[ "$(jq -r '.commit_sha' "${file}")" != "${manifest_commit}" ]]; then
    echo "Manifest and ${profile} policy commit mismatch"
    exit 1
  fi
  if [[ "$(sha256sum "${file}" | awk '{print $1}')" != "$(jq -r --arg p "${profile}" '.compatibility.profiles[$p].kms_policy_sha256' "${tmp_dir}/kms-compatibility-map.json")" ]]; then
    echo "kms-compatibility-map.json records a different sha256 for the ${profile} policy"
    exit 1
  fi
  # A KMS quote must never pass as a node quote, or the other way round: the
  # role is measured into RTMR2 (kernel cmdline) and RTMR3 (boot extend).
  for m in rtmr2 rtmr3; do
    if jq -e --arg m "${m}" '
      [.policy["kms_allowed_\($m)"][] | ascii_downcase] as $k
      | [.policy["node_allowed_\($m)"][] | ascii_downcase] as $n
      | any($n[]; . as $v | $k | index($v) != null)
    ' "${file}" >/dev/null; then
      echo "${profile} ${m} allowlist overlaps between the KMS and node roles"
      exit 1
    fi
  done
done

# KMS profiles must measure apart, so a debug KMS cannot stand in for a locked one.
for pair in "debug debug-read-only" "debug locked-read-only" "debug-read-only locked-read-only"; do
  read -r left right <<< "${pair}"
  if jq -n -e \
    --slurpfile l "${tmp_dir}/kms-attestation-policy.${left}.json" \
    --slurpfile r "${tmp_dir}/kms-attestation-policy.${right}.json" '
    def norm($a): $a | map(ascii_downcase) | sort | unique;
    all(["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"][];
      norm($l[0].policy["kms_allowed_\(.)"]) == norm($r[0].policy["kms_allowed_\(.)"]))
  ' >/dev/null; then
    echo "KMS measurements are identical between ${left} and ${right}"
    exit 1
  fi
done

while read -r checksum archive; do
  manifest_checksum="$(jq -r --arg archive "${archive}" \
    '.binaries[] | select(.file == $archive) | .sha256' "${tmp_dir}/kms-release-manifest.json" | awk 'NR==1')"
  if [[ "${manifest_checksum,,}" != "${checksum,,}" ]]; then
    echo "Checksum mismatch between manifest and kms-checksums.txt for ${archive}"
    exit 1
  fi
done < "${tmp_dir}/kms-checksums.txt"

cert_identity_regex="${COSIGN_CERTIFICATE_IDENTITY_REGEXP:-^https://github.com/${repo}/.github/workflows/release-kms.yaml@refs/heads/master$}"
cert_oidc_issuer="${COSIGN_CERTIFICATE_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

for asset in "${signed_json_assets[@]}" "${archives[@]}"; do
  cosign verify-blob \
    --certificate "${tmp_dir}/${asset}.pem" \
    --signature "${tmp_dir}/${asset}.sig" \
    --certificate-identity-regexp "${cert_identity_regex}" \
    --certificate-oidc-issuer "${cert_oidc_issuer}" \
    "${tmp_dir}/${asset}" >/dev/null
done

echo "Release ${logical_tag}: checksums, manifest, compatibility map, attestation policies, archive hashes and Sigstore signatures verified."
