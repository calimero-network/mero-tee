#!/usr/bin/env bash
set -euo pipefail

# Sign node-image release trust assets with keyless Sigstore.
# Requires prepared artifact files in artifacts/.
#
# Each asset gets a `.bundle.json` beside its `.sig`/`.pem`: the Sigstore bundle
# carries the Rekor inclusion proof, which is what lets a verifier check the
# short-lived Fulcio certificate offline. merod verifies `published-mrtds.json`
# through it when a namespace's TEE policy trusts signed releases.

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
    --bundle "${asset}.bundle.json" \
    "${asset}"
done
