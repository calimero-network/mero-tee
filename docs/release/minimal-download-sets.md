# Minimal Download Sets for Release Verification

This guide defines the smallest artifact set to download per release tag, depending on your verification goal.

Use these sets when you cannot (or do not want to) download all release assets.

## Verification goals

- **Quick verify (operator)**: validate identity/integrity of required runtime artifacts before deployment.
- **Full audit (auditor)**: include provenance transparency and SBOM material for deeper investigation.

## mero-kms-phala release assets

### Quick verify (operator)

- `kms-phala-checksums.txt` + `.sig` + `.pem`
- `kms-phala-release-manifest.json` + `.sig` + `.pem`
- `kms-phala-attestation-policy.json` + `.sig` + `.pem`
- Binary archive(s) for your platform from `kms-phala-checksums.txt` + matching `.sig` + `.pem`

### Full audit (auditor)

Everything in quick verify, plus:

- `kms-phala-rekor-index.json` + `.sig` + `.pem` + `.bundle.json`
- `kms-phala-container-sbom.spdx.json` + `.sig` + `.pem`
- `kms-phala-binaries-sbom.spdx.json` + `.sig` + `.pem`
- `kms-phala-trust-bundle.tar.gz` (+ signature sidecars)
- `kms-phala-compatibility-map.json` + `.sig` + `.pem`

## node-image-gcp release assets

### Quick verify (operator)

- `published-mrtds.json` + `.sig` + `.pem` (MRTDs + measurement policy)
- `release-provenance.json` + `.sig` + `.pem`
- `node-image-gcp-checksums.txt` + `.sig` + `.pem`

### Full audit (auditor)

Everything in quick verify, plus:

- `node-image-gcp-release-sbom.spdx.json` + `.sig` + `.pem`

## Script shortcuts

If you have network access to GitHub Releases, use:

```bash
scripts/release/verify-kms-phala-release-assets.sh <tag>
scripts/release/verify-node-image-gcp-release-assets.sh <tag>
scripts/release/verify-release-assets.sh <tag>
```

Those scripts fetch required artifacts automatically and run policy/signature checks end-to-end.
