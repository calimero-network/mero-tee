#!/usr/bin/env bash
set -euo pipefail

# Create/update the consolidated top-level release entry.
# Inputs: VERSION, KMS_TAG, TARGET_COMMIT, GITHUB_REPOSITORY.
#
# Release mero-kms and Release mero-tee can run concurrently on the same version
# bump; both upsert the same umbrella tag. If two workflows race on
# `gh release create`, the loser must treat "already exists" as success and edit.

if [[ -z "${VERSION:-}" || -z "${KMS_TAG:-}" || -z "${TARGET_COMMIT:-}" ]]; then
  echo "::error::VERSION, KMS_TAG, and TARGET_COMMIT are required"
  exit 1
fi

tee_tag="mero-tee-v${VERSION}"
notes_file="$(mktemp)"
{
  echo "## Consolidated release ${VERSION}"
  echo
  echo "This is an index release that links to component releases:"
  echo
  echo "- mero-kms: https://github.com/${GITHUB_REPOSITORY}/releases/tag/${KMS_TAG}"
  echo "- mero-tee: https://github.com/${GITHUB_REPOSITORY}/releases/tag/${tee_tag}"
} > "${notes_file}"

handle_existing_umbrella() {
  local release_is_draft
  release_is_draft="$(gh release view "${VERSION}" --repo "${GITHUB_REPOSITORY}" --json isDraft --jq '.isDraft' 2>/dev/null || echo "false")"
  if [[ "${release_is_draft}" == "true" ]]; then
    # Publish the umbrella release once links are finalized so it becomes immutable.
    gh release edit "${VERSION}" \
      --repo "${GITHUB_REPOSITORY}" \
      --notes-file "${notes_file}" \
      --title "${VERSION}" \
      --draft=false \
      --latest=false
  else
    echo "Umbrella release ${VERSION} is already published; leaving it unchanged."
  fi
}

if gh release view "${VERSION}" --repo "${GITHUB_REPOSITORY}" >/dev/null 2>&1; then
  handle_existing_umbrella
else
  # Create directly as published/non-latest so the release is immutable at finish.
  if gh release create "${VERSION}" \
    --repo "${GITHUB_REPOSITORY}" \
    --title "${VERSION}" \
    --notes-file "${notes_file}" \
    --target "${TARGET_COMMIT}" \
    --latest=false; then
    :
  else
    if gh release view "${VERSION}" --repo "${GITHUB_REPOSITORY}" >/dev/null 2>&1; then
      echo "::notice::Umbrella release ${VERSION} was created concurrently (e.g. Release mero-tee); reconciling."
      handle_existing_umbrella
    else
      echo "::error::gh release create failed for ${VERSION} and release is still not visible."
      exit 1
    fi
  fi
fi
