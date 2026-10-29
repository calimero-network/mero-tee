#!/usr/bin/env bash
# Create or update the consolidated top-level release `VERSION` that links the
# component releases mero-kms-vVERSION and mero-tee-vVERSION, and make it the
# repository's Latest release once both components are published.
#
# Release mero-kms and Release mero-tee run concurrently on the same version
# bump and both call this. The umbrella is created published, never as a
# draft: a draft has no tag, so `gh release view VERSION` cannot see it, the
# other workflow creates a second (published) release, and the draft is left
# behind for good: an immutable release has taken its tag (2.3.11 ... 2.3.130).
# Drafts named VERSION left by that race are deleted here.
#
# Component releases stay `--latest=false`: Latest is the umbrella of the
# highest version whose two components are published.
#
# Inputs: VERSION, TARGET_COMMIT, GITHUB_REPOSITORY.
set -euo pipefail

if [[ -z "${VERSION:-}" || -z "${TARGET_COMMIT:-}" || -z "${GITHUB_REPOSITORY:-}" ]]; then
  echo "::error::VERSION, TARGET_COMMIT and GITHUB_REPOSITORY are required"
  exit 1
fi

kms_tag="mero-kms-v${VERSION}"
tee_tag="mero-tee-v${VERSION}"
notes_file="$(mktemp)"
trap 'rm -f "${notes_file}"' EXIT
{
  echo "## Consolidated release ${VERSION}"
  echo
  echo "This is an index release that links to component releases:"
  echo
  echo "- mero-kms: https://github.com/${GITHUB_REPOSITORY}/releases/tag/${kms_tag}"
  echo "- mero-tee: https://github.com/${GITHUB_REPOSITORY}/releases/tag/${tee_tag}"
} >"${notes_file}"

# Published: `gh release view TAG` finds it and it is not a draft.
published() {
  [[ "$(gh release view "$1" --repo "${GITHUB_REPOSITORY}" --json isDraft --jq '.isDraft' 2>/dev/null)" == "false" ]]
}

if ! published "${VERSION}"; then
  if ! gh release create "${VERSION}" \
    --repo "${GITHUB_REPOSITORY}" \
    --title "${VERSION}" \
    --notes-file "${notes_file}" \
    --target "${TARGET_COMMIT}" \
    --latest=false; then
    if published "${VERSION}"; then
      echo "::notice::Umbrella release ${VERSION} was created concurrently by the other release workflow."
    else
      echo "::error::gh release create failed for ${VERSION} and no published release has that tag."
      exit 1
    fi
  fi
fi

# Drafts named VERSION are leftovers of the race above (or of the old
# create-as-draft path): the published release owns the tag, so they can never
# be published.
gh api --paginate "repos/${GITHUB_REPOSITORY}/releases?per_page=100" \
  --jq ".[] | select(.draft and .name == \"${VERSION}\") | .id" |
  while read -r id; do
    [[ -n "${id}" ]] || continue
    echo "Deleting orphan draft release ${id} (${VERSION})"
    gh api -X DELETE "repos/${GITHUB_REPOSITORY}/releases/${id}" ||
      echo "::warning::could not delete orphan draft release ${id}"
  done

if ! published "${kms_tag}" || ! published "${tee_tag}"; then
  echo "Not marking ${VERSION} Latest yet: ${kms_tag} and ${tee_tag} are not both published."
  exit 0
fi

# Latest only moves forward: an older version's rerun never takes it back.
highest="$(
  gh release list --repo "${GITHUB_REPOSITORY}" --exclude-drafts --limit 200 --json tagName --jq '.[].tagName' |
    { grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' || true; } | sort -V | tail -n 1
)"
if [[ "${highest}" != "${VERSION}" ]]; then
  echo "Not marking ${VERSION} Latest: ${highest} is newer."
  exit 0
fi
if gh release edit "${VERSION}" --repo "${GITHUB_REPOSITORY}" --latest; then
  echo "Marked ${VERSION} as the Latest release."
else
  echo "::warning::could not mark ${VERSION} as the Latest release"
fi
