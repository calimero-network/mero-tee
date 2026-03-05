#!/usr/bin/env bash
set -euo pipefail

tag="${1:-}"
if [[ -z "${tag}" ]]; then
  echo "Usage: $0 <X.Y.Z>"
  exit 1
fi

required_commands=(jq curl git)
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

fetch_release_assets() {
  local release_tag="$1"
  if [[ "${has_gh}" == "true" ]]; then
    gh release view "${release_tag}" --repo "${repo}" --json assets --jq '[.assets[].name]' 2>/dev/null || true
    return
  fi

  curl -fsSL "${api_headers[@]}" \
    "https://api.github.com/repos/${repo}/releases/tags/${release_tag}" \
    | jq -c '[.assets[]?.name]' 2>/dev/null || true
}

assets_json="$(fetch_release_assets "${tag}")"
if [[ -z "${assets_json}" || "${assets_json}" == "null" ]]; then
  echo "Release '${tag}' not found in ${repo}"
  exit 1
fi

has_kms_assets="$(jq -r 'any(.[]; . == "mero-kms-phala-checksums.txt")' <<< "${assets_json}")"
has_locked_assets="$(jq -r 'any(.[]; . == "merod-locked-image-checksums.txt" or . == "locked-image-checksums.txt")' <<< "${assets_json}")"

if [[ "${has_kms_assets}" != "true" && "${has_locked_assets}" != "true" ]]; then
  echo "No known trust asset sets found for release '${tag}' in ${repo}"
  exit 1
fi

echo "Verifying release ${tag} in ${repo}..."

if [[ "${has_kms_assets}" == "true" ]]; then
  echo "-> Verifying KMS release asset set"
  scripts/verify_mero_kms_release_assets.sh "${tag}"
else
  echo "-> KMS asset set not present; skipping"
fi

if [[ "${has_locked_assets}" == "true" ]]; then
  echo "-> Verifying locked-image release asset set"
  scripts/verify_locked_image_release_assets.sh "${tag}"
else
  echo "-> Locked-image asset set not present; skipping"
fi

echo "Release ${tag} verification completed."
