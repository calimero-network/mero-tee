# Trust & Verification

This page is the single entry point for how trust is established for released artifacts in `mero-tee`.

## Scope

This repository publishes two trust-asset families per release tag:

1. **KMS release assets** on tag `X.Y.Z` (`mero-kms-phala` binaries + policy/manifest/signatures)
2. **Locked-image assets** on tag `locked-image-vX.Y.Z` (MRTDs, policy, release provenance, signatures)

## What signatures prove (and do not prove)

- **Proves**: an artifact was produced by the expected GitHub Actions workflow identity and was not modified after signing.
- **Does not prove**: source code quality, absence of vulnerabilities, or fitness for your deployment model.

Use signatures together with:

- policy review (`merod-locked-image-policy.json`, `mero-kms-phala-attestation-policy.json`)
- compatibility checks (`policies/index.json` + compatibility map artifacts)
- runtime quote verification for deployed nodes

## Canonical verification commands

```bash
scripts/verify_mero_kms_release_assets.sh <tag>
scripts/verify_locked_image_release_assets.sh <tag>
scripts/verify_all_release_assets.sh <tag>
```

## Verification workflow identities

Keyless signatures are expected from these workflow identities on `master`:

- `https://github.com/<org>/<repo>/.github/workflows/release-mero-kms-phala.yaml@refs/heads/master`
- `https://github.com/<org>/<repo>/.github/workflows/gcp_locked_image_build.yaml@refs/heads/master`

OIDC issuer is expected to be:

- `https://token.actions.githubusercontent.com`

## Recommended operator flow

1. Pick the release tag you plan to deploy.
2. Run `scripts/verify_all_release_assets.sh <tag>`.
3. Generate release-pinned config snippets for `merod` using:
   - `scripts/generate_merod_kms_attestation_config.sh`
4. Roll out with digest-pinned images and release-pinned policy/config.

## Related docs

- [TEE verification for beginners](TEE_VERIFICATION_FOR_BEGINNERS.md)
- [Verify MRTD](verify-mrtd.md)
- [Release verification examples](release-verification-examples.md)
- [Architecture](ARCHITECTURE.md)
- [Release taxonomy](RELEASE_TAXONOMY.md)
- [Documentation source index](DOCS_INDEX.md)
