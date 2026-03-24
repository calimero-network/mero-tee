#!/usr/bin/env bash
set -euo pipefail

# Create/update the consolidated top-level release entry.
# Inputs: VERSION, TARGET_COMMIT, GITHUB_REPOSITORY.
#
# Release mero-tee and Release mero-kms can run concurrently on the same version
# bump; both upsert the same umbrella tag. If two workflows race on
# `gh release create`, the loser must treat "already exists" as success and edit.

if [[ -z "${VERSION:-}" || -z "${TARGET_COMMIT:-}" ]]; then
  echo "::error::VERSION and TARGET_COMMIT are required"
  exit 1
fi

kms_tag="mero-kms-v${VERSION}"
tee_tag="mero-tee-v${VERSION}"
notes_file="$(mktemp)"
{
  echo "## Consolidated release ${VERSION}"
  echo
  echo "This is an index release that links to component releases:"
  echo
  echo "- mero-kms: https://github.com/${GITHUB_REPOSITORY}/releases/tag/${kms_tag}"
  echo "- mero-tee: https://github.com/${GITHUB_REPOSITORY}/releases/tag/${tee_tag}"
} > "${notes_file}"

apply_notes_for_existing_release() {
  local release_is_draft
  release_is_draft="$(gh release view "${VERSION}" --repo "${GITHUB_REPOSITORY}" --json isDraft --jq '.isDraft' 2>/dev/null || echo "false")"
  if [[ "${release_is_draft}" == "true" ]]; then
    # Keep as draft; KMS will publish when it runs
    gh release edit "${VERSION}" --repo "${GITHUB_REPOSITORY}" --notes-file "${notes_file}" --title "${VERSION}" --draft
  else
    # Already published by KMS; update notes only, do not touch draft status
    gh release edit "${VERSION}" --repo "${GITHUB_REPOSITORY}" --notes-file "${notes_file}" --title "${VERSION}"
  fi
}

if gh release view "${VERSION}" --repo "${GITHUB_REPOSITORY}" >/dev/null 2>&1; then
  apply_notes_for_existing_release
else
  if gh release create "${VERSION}" --repo "${GITHUB_REPOSITORY}" --title "${VERSION}" --notes-file "${notes_file}" --target "${TARGET_COMMIT}" --draft; then
    :
  else
    if gh release view "${VERSION}" --repo "${GITHUB_REPOSITORY}" >/dev/null 2>&1; then
      echo "::notice::Umbrella release ${VERSION} was created concurrently (e.g. Release mero-kms); updating notes only."
      apply_notes_for_existing_release
    else
      echo "::error::gh release create failed for ${VERSION} and release is still not visible."
      exit 1
    fi
  fi
fi
