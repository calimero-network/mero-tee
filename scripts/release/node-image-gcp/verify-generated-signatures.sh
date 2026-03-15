#!/usr/bin/env bash
set -euo pipefail

assets=(
  "artifacts/published-mrtds.json"
  "artifacts/release-provenance.json"
  "artifacts/node-image-gcp-release-sbom.spdx.json"
  "artifacts/node-image-gcp-checksums.txt"
)

cert_identity_regex="^https://github.com/${GITHUB_REPOSITORY}/.github/workflows/release-node-image-gcp.yaml@refs/heads/master$"
cert_oidc_issuer="https://token.actions.githubusercontent.com"

for asset in "${assets[@]}"; do
  cosign verify-blob \
    --certificate "${asset}.pem" \
    --signature "${asset}.sig" \
    --certificate-identity-regexp "${cert_identity_regex}" \
    --certificate-oidc-issuer "${cert_oidc_issuer}" \
    "${asset}"
done
