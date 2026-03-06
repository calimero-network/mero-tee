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
elif [[ "${logical_tag}" == mero-tee-v* ]]; then
  logical_tag="${logical_tag#mero-tee-v}"
elif [[ "${logical_tag}" == node-image-gcp-v* ]]; then
  logical_tag="${logical_tag#node-image-gcp-v}"
fi

required_commands=(git)
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
kms_release_tag="${tag}"
node_release_tag="${tag}"
if [[ "${tag}" != mero-kms-v* ]]; then
  kms_release_tag="mero-kms-v${logical_tag}"
fi
if [[ "${tag}" != mero-tee-v* ]]; then
  node_release_tag="mero-tee-v${logical_tag}"
fi

echo "Verifying release ${logical_tag} in ${repo}..."
echo "-> Verifying mero-kms release asset set from ${kms_release_tag}"
scripts/release/verify-kms-phala-release-assets.sh "${kms_release_tag}"

echo "-> Verifying mero-tee release asset set from ${node_release_tag}"
scripts/release/verify-node-image-gcp-release-assets.sh "${node_release_tag}"

echo "Release ${logical_tag} verification completed."
