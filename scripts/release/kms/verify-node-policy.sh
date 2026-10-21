#!/usr/bin/env bash
set -euo pipefail

# Verify a node release's published-mrtds.json before a KMS image is built from it.
# Usage: verify-node-policy.sh <dir>   (holding published-mrtds.json and its .bundle.json)
# Inputs: GITHUB_REPOSITORY.
#
# The KMS image bakes this file's measurements into its measured kms.env, and the
# KMS release then signs that image as official. So whatever the file says, an
# official KMS releases keys to. The file comes from a GitHub release, which any
# collaborator, or anyone holding a release token, can edit. What they cannot do
# is sign as `release-node-image-gcp.yaml` on master, which is the only identity
# accepted here: the same one verify-node-image-gcp-release-assets.sh and merod
# check, through the bundle's Rekor inclusion proof.

dir="${1:?usage: verify-node-policy.sh <dir>}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

policy="${dir}/published-mrtds.json"
bundle="${policy}.bundle.json"
for file in "${policy}" "${bundle}"; do
  if [[ ! -s "${file}" ]]; then
    echo "::error::${file} is missing; refusing a node policy with no signature"
    exit 1
  fi
done

cosign verify-blob \
  --bundle "${bundle}" \
  --certificate-identity-regexp "^https://github.com/${GITHUB_REPOSITORY}/.github/workflows/release-node-image-gcp.yaml@refs/heads/master$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${policy}"
