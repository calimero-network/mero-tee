#!/usr/bin/env bash
set -euo pipefail

target_commit="${TARGET_COMMIT:-${GITHUB_SHA:-}}"
if [[ -z "${target_commit}" ]]; then
  echo "::error::TARGET_COMMIT (or GITHUB_SHA) is required"
  exit 1
fi

if [[ -z "${GITHUB_OUTPUT:-}" ]]; then
  echo "::error::GITHUB_OUTPUT is required"
  exit 1
fi

echo "target_commit=${target_commit}" >> "${GITHUB_OUTPUT}"

version="$(cargo metadata --format-version 1 --no-deps 2>/dev/null | jq -r '.packages[] | select(.name=="mero-kms-phala") | .version' || echo "0.1.0")"
if [[ -z "${version}" || "${version}" == "null" ]]; then
  version="0.1.0"
fi
kms_release_tag="mero-kms-v${version}"

prerelease=false
binary_release=false
docker_release=false

if [[ "${GH_REF:-${GITHUB_REF:-}}" == "refs/heads/master" ]]; then
  if [[ "${version}" =~ -[a-z]+(\.[0-9]+)?$ ]]; then
    prerelease=true
  fi
  if ! gh release view "${kms_release_tag}" --repo "${GITHUB_REPOSITORY}" >/dev/null 2>&1; then
    binary_release=true
    docker_release=true
  fi
elif [[ "${GITHUB_EVENT_NAME:-}" == "pull_request" ]]; then
  docker_release=true
fi

echo "version=${version}" >> "${GITHUB_OUTPUT}"
echo "kms_release_tag=${kms_release_tag}" >> "${GITHUB_OUTPUT}"
echo "prerelease=${prerelease}" >> "${GITHUB_OUTPUT}"
echo "binary_release=${binary_release}" >> "${GITHUB_OUTPUT}"
echo "docker_release=${docker_release}" >> "${GITHUB_OUTPUT}"
