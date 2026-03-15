#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${RUN_ID:-}" ]]; then
  echo "::error::RUN_ID is required"
  exit 1
fi

if [[ -z "${GITHUB_OUTPUT:-}" ]]; then
  echo "::error::GITHUB_OUTPUT is required"
  exit 1
fi

artifact_name="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${RUN_ID}/artifacts" \
  --jq '.artifacts | map(select(.expired == false and (.name | startswith("kms-staging-probe-")))) | sort_by(.created_at) | reverse | .[0].name // ""')"
if [[ -z "${artifact_name}" ]]; then
  echo "::error::No probe artifact found for run ${RUN_ID}"
  exit 1
fi
echo "artifact_name=${artifact_name}" >> "${GITHUB_OUTPUT}"
mkdir -p probe-artifacts
gh run download "${RUN_ID}" --repo "${GITHUB_REPOSITORY}" --name "${artifact_name}" --dir probe-artifacts
