#!/usr/bin/env bash
set -euo pipefail

# Create/update the consolidated top-level release entry.
# Inputs: VERSION, TARGET_COMMIT, GITHUB_REPOSITORY.

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

if gh release view "${VERSION}" --repo "${GITHUB_REPOSITORY}" >/dev/null 2>&1; then
  gh release edit "${VERSION}" --repo "${GITHUB_REPOSITORY}" --notes-file "${notes_file}" --title "${VERSION}" --draft
else
  gh release create "${VERSION}" --repo "${GITHUB_REPOSITORY}" --title "${VERSION}" --notes-file "${notes_file}" --target "${TARGET_COMMIT}" --draft
fi
