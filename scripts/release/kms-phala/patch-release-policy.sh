#!/usr/bin/env bash
# One-off: patch a KMS release with policy assets from a source release.
# Usage: KMS_TAG=mero-kms-v2.1.87 SOURCE_TAG=mero-kms-v2.1.85 [TARGET_COMMIT=<sha>] ./patch-release-policy.sh
# If release exists: upload assets. If not: create draft then upload.
# TARGET_COMMIT required only when creating; use the commit that has the version in Cargo.toml.
set -euo pipefail

KMS_TAG="${KMS_TAG:?}"
SOURCE_TAG="${SOURCE_TAG:?}"
REPO="${GITHUB_REPOSITORY:-calimero-network/mero-tee}"

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

echo "Downloading policy from ${SOURCE_TAG}..."
for asset in kms-phala-attestation-policy.json \
  kms-phala-attestation-policy.debug.json \
  kms-phala-attestation-policy.debug-read-only.json \
  kms-phala-attestation-policy.locked-read-only.json; do
  gh release download "${SOURCE_TAG}" --repo "${REPO}" \
    --pattern "${asset}" --dir "${workdir}" 2>/dev/null || true
done

if [[ ! -f "${workdir}/kms-phala-attestation-policy.json" ]]; then
  echo "::error::Source ${SOURCE_TAG} has no kms-phala-attestation-policy.json"
  exit 1
fi

for profile in locked-read-only debug debug-read-only; do
  f="${workdir}/kms-phala-attestation-policy.${profile}.json"
  [[ -f "${f}" ]] || cp "${workdir}/kms-phala-attestation-policy.json" "${f}"
done

if ! gh release view "${KMS_TAG}" --repo "${REPO}" >/dev/null 2>&1; then
  if [[ -z "${TARGET_COMMIT:-}" ]]; then
    echo "::error::Release ${KMS_TAG} does not exist. Set TARGET_COMMIT to create it."
    exit 1
  fi
  echo "Creating draft release ${KMS_TAG}..."
  echo "Minimal patch release for policy fetch." > "${workdir}/notes.md"
  gh release create "${KMS_TAG}" --repo "${REPO}" \
    --title "${KMS_TAG}" --notes-file "${workdir}/notes.md" \
    --target "${TARGET_COMMIT}" --draft
fi

echo "Uploading policy assets to ${KMS_TAG}..."
gh release upload "${KMS_TAG}" --repo "${REPO}" \
  "${workdir}"/kms-phala-attestation-policy.json \
  "${workdir}"/kms-phala-attestation-policy.debug.json \
  "${workdir}"/kms-phala-attestation-policy.debug-read-only.json \
  "${workdir}"/kms-phala-attestation-policy.locked-read-only.json \
  --clobber

echo "Patched ${KMS_TAG} with policy from ${SOURCE_TAG}."
