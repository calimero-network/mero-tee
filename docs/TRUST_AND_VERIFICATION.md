# Trust & Verification

This page is the single entry point for how trust is established for released artifacts in `mero-tee`.

## Scope

This repository publishes two trust-asset families per release tag:

1. **KMS release assets** on tag `X.Y.Z` (`mero-kms-phala` binaries + policy/manifest/signatures)
2. **Locked-image assets** on tag `locked-image-vX.Y.Z` (MRTDs, policy, release provenance, signatures)

These map to two deployment lanes with different responsibilities:

- **Phala KMS lane** (operate `mero-kms-phala`): [platforms/phala-kms.md](platforms/phala-kms.md)
- **GCP node lane** (deploy locked `merod` image): [platforms/gcp-merod.md](platforms/gcp-merod.md)

## What signatures prove (and do not prove)

- **Proves**: an artifact was produced by the expected GitHub Actions workflow identity and was not modified after signing.
- **Does not prove**: source code quality, absence of vulnerabilities, or fitness for your deployment model.

Use signatures together with:

- policy review (`merod-locked-image-policy.json`, `mero-kms-phala-attestation-policy.json`)
- compatibility checks (`policies/index.json` + compatibility map artifacts)
- runtime quote verification for deployed nodes

## Canonical verification commands

```bash
scripts/verify-kms-phala-release-assets.sh <tag>
scripts/verify-node-image-gcp-release-assets.sh <tag>
scripts/verify-release-assets.sh <tag>
```

## Verification workflow identities

Keyless signatures are expected from these workflow identities on `master`:

- `https://github.com/<org>/<repo>/.github/workflows/release-kms-phala.yaml@refs/heads/master`
- `https://github.com/<org>/<repo>/.github/workflows/release-node-image-gcp.yaml@refs/heads/master`

OIDC issuer is expected to be:

- `https://token.actions.githubusercontent.com`

## Recommended operator flow

1. Pick the release tag you plan to deploy.
2. Run `scripts/verify-release-assets.sh <tag>`.
3. Generate release-pinned config snippets for `merod` using:
   - `scripts/generate-merod-kms-phala-attestation-config.sh`
4. Roll out with digest-pinned images and release-pinned policy/config.

## Related docs

- [TEE verification for beginners](TEE_VERIFICATION_FOR_BEGINNERS.md)
- [Platform runbooks](platforms/README.md)
- [Verify MRTD](verify-mrtd.md)
- [Release verification examples](release-verification-examples.md)
- [Architecture](ARCHITECTURE.md)
- [Release taxonomy](RELEASE_TAXONOMY.md)
- [Documentation source index](DOCS_INDEX.md)
