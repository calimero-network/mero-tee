#!/usr/bin/env bash
set -euo pipefail

# Verify all generated KMS signatures/certificates against workflow identity.
# Inputs: GH_REPOSITORY and COSIGN_CERTIFICATE_OIDC_ISSUER.

cert_identity_regex="^https://github.com/${GH_REPOSITORY}/.github/workflows/release-kms-phala.yaml@refs/heads/master$"
signed_assets=(
  artifacts/*.tar.gz
  release-assets/kms-phala-checksums.txt
  release-assets/kms-phala-release-manifest.json
  release-assets/kms-phala-attestation-policy.json
  release-assets/kms-phala-attestation-policy.debug.json
  release-assets/kms-phala-attestation-policy.debug-read-only.json
  release-assets/kms-phala-attestation-policy.locked-read-only.json
  release-assets/kms-phala-container-metadata.json
  release-assets/kms-phala-container-sbom.spdx.json
  release-assets/kms-phala-binaries-sbom.spdx.json
  release-assets/kms-phala-trust-bundle.tar.gz
  release-assets/kms-phala-compatibility-map.json
  release-assets/kms-phala-rekor-index.json
)

for asset in "${signed_assets[@]}"; do
  base_name="$(basename "${asset}")"
  cosign verify-blob \
    --certificate "release-assets/${base_name}.pem" \
    --signature "release-assets/${base_name}.sig" \
    --certificate-identity-regexp "${cert_identity_regex}" \
    --certificate-oidc-issuer "${COSIGN_CERTIFICATE_OIDC_ISSUER}" \
    "${asset}" >/dev/null
done
