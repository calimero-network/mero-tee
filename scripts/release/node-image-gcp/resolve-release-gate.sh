#!/usr/bin/env bash
set -euo pipefail

# Decide whether node-image release should proceed and resolve merod tag.
# Inputs: GITHUB_REF, GITHUB_EVENT_NAME, GH_TOKEN, mero-tee/versions.json.
# Outputs (GITHUB_OUTPUT): run_pipeline, latest_merod_version, reason.

if [[ -z "${GH_TOKEN:-}" ]]; then
  echo "::error::GH_TOKEN is required"
  exit 1
fi

if [[ -z "${GITHUB_OUTPUT:-}" ]]; then
  echo "::error::GITHUB_OUTPUT is required"
  exit 1
fi

run_pipeline="false"
reason=""
latest_merod_version=""
allow_non_master="false"
if [[ "${GITHUB_EVENT_NAME}" == "workflow_dispatch" ]]; then
  allow_non_master="true"
fi

if [[ "${GITHUB_REF}" != "refs/heads/master" && "${allow_non_master}" != "true" ]]; then
  reason="Workflow is restricted to refs/heads/master; current ref is ${GITHUB_REF}."
  {
    echo "run_pipeline=${run_pipeline}"
    echo "latest_merod_version=${latest_merod_version}"
    echo "reason=${reason}"
  } >> "${GITHUB_OUTPUT}"
  exit 0
fi

# Prefer merodVersion from versions.json (supports RC/pre-releases; releases/latest excludes them)
pinned_version="$(jq -r '.merodVersion // empty' mero-tee/versions.json)"
if [[ -n "${pinned_version}" ]]; then
  echo "Using merodVersion from versions.json: ${pinned_version}"
  release_json="$(curl -fsSL \
    --retry 5 \
    --retry-delay 2 \
    --retry-all-errors \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer ${GH_TOKEN}" \
    "https://api.github.com/repos/calimero-network/core/releases/tags/${pinned_version}")"
  if ! jq -e '.tag_name' <<< "${release_json}" >/dev/null 2>&1; then
    echo "::error::Core release '${pinned_version}' not found. Check that the tag exists (including RC/pre-releases)."
    exit 1
  fi
  latest_merod_version="${pinned_version}"
else
  release_json="$(curl -fsSL \
    --retry 5 \
    --retry-delay 2 \
    --retry-all-errors \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer ${GH_TOKEN}" \
    "https://api.github.com/repos/calimero-network/core/releases/latest")"
  latest_merod_version="$(jq -r '.tag_name // empty' <<< "${release_json}")"
  if [[ -z "${latest_merod_version}" ]]; then
    echo "Unable to resolve latest calimero-network/core release tag."
    exit 1
  fi
fi

for required_asset in \
  "merod_x86_64-unknown-linux-gnu.tar.gz" \
  "meroctl_x86_64-unknown-linux-gnu.tar.gz" \
  "mero-auth_x86_64-unknown-linux-gnu.tar.gz"; do
  if ! jq -e --arg asset "${required_asset}" '.assets | any(.name == $asset)' <<< "${release_json}" >/dev/null; then
    echo "::error::Core release '${latest_merod_version}' missing required asset: ${required_asset}"
    exit 1
  fi
done

run_pipeline="true"
if [[ "${GITHUB_REF}" == "refs/heads/master" ]]; then
  reason="Detected mero-tee/versions.json change on master."
else
  reason="Manual workflow_dispatch run enabled on non-master ref ${GITHUB_REF}."
fi

{
  echo "run_pipeline=${run_pipeline}"
  echo "latest_merod_version=${latest_merod_version}"
  echo "reason=${reason}"
} >> "${GITHUB_OUTPUT}"
