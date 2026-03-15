#!/usr/bin/env bash
set -euo pipefail

assets=(
  "artifacts/published-mrtds.json"
  "artifacts/release-provenance.json"
  "artifacts/node-image-gcp-release-sbom.spdx.json"
  "artifacts/node-image-gcp-checksums.txt"
)

for asset in "${assets[@]}"; do
  if [[ ! -f "${asset}" ]]; then
    echo "Missing asset to sign: ${asset}"
    exit 1
  fi
  cosign sign-blob \
    --yes \
    --output-signature "${asset}.sig" \
    --output-certificate "${asset}.pem" \
    "${asset}"
done
