#!/usr/bin/env bash
set -euo pipefail

# Verify all generated KMS signatures/certificates against workflow identity.
# Inputs: GH_REPOSITORY and COSIGN_CERTIFICATE_OIDC_ISSUER.

cert_identity_regex="^https://github.com/${GH_REPOSITORY}/.github/workflows/release-kms.yaml@refs/heads/master$"
signed_assets=(
  artifacts/*.tar.gz
  release-assets/kms-checksums.txt
  release-assets/kms-release-manifest.json
  release-assets/kms-attestation-policy.json
  release-assets/kms-attestation-policy.debug.json
  release-assets/kms-attestation-policy.debug-read-only.json
  release-assets/kms-attestation-policy.locked-read-only.json
  release-assets/kms-binaries-sbom.spdx.json
  release-assets/kms-trust-bundle.tar.gz
  release-assets/kms-compatibility-map.json
  release-assets/kms-rekor-index.json
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
