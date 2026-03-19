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
# Optional: BOOTSTRAP_POLICY_SOURCE_TAG (defaults to mero-kms-v2.1.85).
# Requires: GH_TOKEN.

if [[ -z "${VERSION:-}" || -z "${KMS_TAG:-}" || -z "${TARGET_COMMIT:-}" ]]; then
  echo "::error::VERSION, KMS_TAG, and TARGET_COMMIT are required"
  exit 1
fi

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

bootstrap_policy_source_tag="${BOOTSTRAP_POLICY_SOURCE_TAG:-mero-kms-v2.1.85}"
if [[ "${bootstrap_policy_source_tag}" == "${KMS_TAG}" ]]; then
  echo "::error::BOOTSTRAP_POLICY_SOURCE_TAG must differ from KMS_TAG for minimal bootstrap policy copy."
  exit 1
fi

if ! gh release view "${bootstrap_policy_source_tag}" --repo "${GITHUB_REPOSITORY}" >/dev/null 2>&1; then
  echo "::error::Bootstrap policy source release ${bootstrap_policy_source_tag} was not found."
  exit 1
fi

echo "Downloading bootstrap policy from ${bootstrap_policy_source_tag}..."
if ! gh release download "${bootstrap_policy_source_tag}" --repo "${GITHUB_REPOSITORY}" \
  --pattern "kms-phala-attestation-policy.json" --dir "${workdir}" 2>/dev/null; then
  echo "::error::Bootstrap policy source ${bootstrap_policy_source_tag} is missing kms-phala-attestation-policy.json."
  exit 1
fi

for asset in kms-phala-attestation-policy.json \
  kms-phala-attestation-policy.debug.json \
  kms-phala-attestation-policy.debug-read-only.json \
  kms-phala-attestation-policy.locked-read-only.json; do
  gh release download "${bootstrap_policy_source_tag}" --repo "${GITHUB_REPOSITORY}" \
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
