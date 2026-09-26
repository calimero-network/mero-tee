#!/usr/bin/env bash
set -euo pipefail

# Resolve KMS release metadata for workflow jobs.
# Inputs: TARGET_COMMIT/GITHUB_SHA, GH_REF/GITHUB_REF, GITHUB_EVENT_NAME,
# GITHUB_REPOSITORY.
# Outputs (GITHUB_OUTPUT): target_commit, version, kms_release_tag, and
# publish_release -- true only for a push to master when the release tag does
# not exist yet, so a branch run can never publish or build release images.
# merod accepts a policy only when its signing certificate names a push-
# triggered run (KMS_RELEASE_IDENTITY in core), so a manual dispatch would
# publish a release no node could use; re-run a failed release's jobs instead,
# which keeps the original push event.

target_commit="${TARGET_COMMIT:-${GITHUB_SHA:-}}"
if [[ -z "${target_commit}" ]]; then
  echo "::error::TARGET_COMMIT (or GITHUB_SHA) is required"
  exit 1
fi

if [[ -z "${GITHUB_OUTPUT:-}" ]]; then
  echo "::error::GITHUB_OUTPUT is required"
  exit 1
fi

version="$(cargo metadata --format-version 1 --no-deps 2>/dev/null | jq -r '.packages[] | select(.name=="mero-kms") | .version' || echo "0.1.0")"
if [[ -z "${version}" || "${version}" == "null" ]]; then
  version="0.1.0"
fi
kms_release_tag="mero-kms-v${version}"

publish_release=false
if [[ "${GH_REF:-${GITHUB_REF:-}}" == "refs/heads/master" ]] \
  && [[ "${GITHUB_EVENT_NAME:-}" == "push" ]] \
  && ! gh release view "${kms_release_tag}" --repo "${GITHUB_REPOSITORY}" >/dev/null 2>&1; then
  publish_release=true
fi

{
  echo "target_commit=${target_commit}"
  echo "version=${version}"
  echo "kms_release_tag=${kms_release_tag}"
  echo "publish_release=${publish_release}"
} >> "${GITHUB_OUTPUT}"
