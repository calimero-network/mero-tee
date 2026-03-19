#!/usr/bin/env bash
set -euo pipefail

# Publish a minimal mero-kms release so the KMS can fetch policy at boot.
# The probe needs the release to exist so KMS can fetch policy at boot. We copy policy files
# from the previous release as a bootstrap; release-metadata will overwrite with real policy.
#
# Note: Bootstrap policy allows the previous image's measurements. If the new image has
# different TEE measurements, the probe may fail. This typically works when the build
# produces stable measurements across minor releases.
#
# Inputs: VERSION, KMS_TAG, TARGET_COMMIT, GITHUB_REPOSITORY.
# Requires: GH_TOKEN.

if [[ -z "${VERSION:-}" || -z "${KMS_TAG:-}" || -z "${TARGET_COMMIT:-}" ]]; then
  echo "::error::VERSION, KMS_TAG, and TARGET_COMMIT are required"
  exit 1
fi

# Find the latest release (excluding current) that has policy assets.
# Iterate newest-first; use first one we can successfully download from.
workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

candidate_tags="$(gh release list --repo "${GITHUB_REPOSITORY}" --limit 30 --json tagName -q '.[].tagName' 2>/dev/null \
  | grep -E '^mero-kms-v[0-9]+\.[0-9]+\.[0-9]+$' \
  | grep -v "^${KMS_TAG}$" || true)"

prev_tag=""
for tag in ${candidate_tags}; do
  echo "Trying ${tag}..."
  rm -rf "${workdir:?}"/* 2>/dev/null || true
  if gh release download "${tag}" --repo "${GITHUB_REPOSITORY}" \
    --pattern "kms-phala-attestation-policy.json" --dir "${workdir}" 2>/dev/null; then
    prev_tag="${tag}"
    echo "Found policy in ${tag}"
    break
  fi
done

if [[ -z "${prev_tag}" ]]; then
  echo "::error::No mero-kms release with kms-phala-attestation-policy.json found. Cannot bootstrap minimal release."
  exit 1
fi

echo "Downloading policy from ${prev_tag} for bootstrap..."
for asset in kms-phala-attestation-policy.json \
  kms-phala-attestation-policy.debug.json \
  kms-phala-attestation-policy.debug-read-only.json \
  kms-phala-attestation-policy.locked-read-only.json; do
  gh release download "${prev_tag}" --repo "${GITHUB_REPOSITORY}" \
    --pattern "${asset}" --dir "${workdir}" 2>/dev/null || true
done

# Ensure all profile policies exist (copy main if missing)
for profile in locked-read-only debug debug-read-only; do
  f="${workdir}/kms-phala-attestation-policy.${profile}.json"
  if [[ ! -f "${f}" ]]; then
    cp "${workdir}/kms-phala-attestation-policy.json" "${f}"
  fi
done

notes_file="${workdir}/notes.md"
echo "Minimal bootstrap release for compose_hash alignment. Full assets will be published by release-metadata." > "${notes_file}"

echo "Creating minimal release ${KMS_TAG} (draft)..."
if ! gh release create "${KMS_TAG}" \
  --repo "${GITHUB_REPOSITORY}" \
  --title "${KMS_TAG}" \
  --notes-file "${notes_file}" \
  --target "${TARGET_COMMIT}" \
  --draft; then
  if gh release view "${KMS_TAG}" --repo "${GITHUB_REPOSITORY}" >/dev/null 2>&1; then
    echo "Release ${KMS_TAG} already exists; will upload/overwrite policy assets."
  else
    echo "::error::Failed to create release ${KMS_TAG}"
    exit 1
  fi
fi

echo "Uploading bootstrap policy assets..."
gh release upload "${KMS_TAG}" \
  --repo "${GITHUB_REPOSITORY}" \
  "${workdir}"/kms-phala-attestation-policy.json \
  "${workdir}"/kms-phala-attestation-policy.debug.json \
  "${workdir}"/kms-phala-attestation-policy.debug-read-only.json \
  "${workdir}"/kms-phala-attestation-policy.locked-read-only.json \
  --clobber

echo "Minimal release ${KMS_TAG} published (draft). KMS uses CARGO_PKG_VERSION=${VERSION} to fetch policy."
