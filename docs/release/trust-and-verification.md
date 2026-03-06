# Trust & Verification

This page is the single entry point for how trust is established for released artifacts in `mero-tee`.

## Scope

This repository publishes two trust-asset families per release tag:

1. **KMS release assets** on tag `X.Y.Z` (`mero-kms-phala` binaries + policy/manifest/signatures)
2. **node-image-gcp assets** on tag `mero-tee-vX.Y.Z` (MRTDs, policy, release provenance, signatures)

These map to two deployment lanes with different responsibilities:

- **Phala KMS lane** (operate `mero-kms-phala`): [../runbooks/platforms/phala-kms.md](../runbooks/platforms/phala-kms.md)
- **GCP node lane** (deploy locked `merod` image): [../runbooks/platforms/gcp-merod.md](../runbooks/platforms/gcp-merod.md)

## What signatures prove (and do not prove)

- **Proves**: an artifact was produced by the expected GitHub Actions workflow identity and was not modified after signing.
- **Does not prove**: source code quality, absence of vulnerabilities, or fitness for your deployment model.

Use signatures together with:

- policy review (`node-image-gcp-policy.json`, `kms-phala-attestation-policy.json`)
- compatibility checks (`policies/index.json` + compatibility map artifacts)
- runtime quote verification for deployed nodes

## Canonical verification commands

```bash
scripts/release/verify-kms-phala-release-assets.sh <tag>
scripts/release/verify-node-image-gcp-release-assets.sh <tag>
scripts/release/verify-release-assets.sh <tag>
```

## Verification workflow identities

Keyless signatures are expected from these workflow identities on `master`:

- `https://github.com/<org>/<repo>/.github/workflows/release-kms-phala.yaml@refs/heads/master`
- `https://github.com/<org>/<repo>/.github/workflows/release-node-image-gcp.yaml@refs/heads/master`

OIDC issuer is expected to be:

- `https://token.actions.githubusercontent.com`

## Recommended operator flow

1. Pick the release tag you plan to deploy.
2. Run `scripts/release/verify-release-assets.sh <tag>`.
3. Generate release-pinned config snippets for `merod` using:
   - `scripts/policy/generate-merod-kms-phala-attestation-config.sh`
4. Roll out with digest-pinned images and release-pinned policy/config.

## Related docs

- [TEE verification for beginners](verification-beginner.md)
- [Platform runbooks](../runbooks/platforms/README.md)
- [Verify MRTD](../runbooks/operations/verify-mrtd.md)
- [Release verification examples](verification-examples.md)
- [Architecture](../architecture/trust-boundaries.md)
- [Release taxonomy](taxonomy.md)
- [Documentation source index](../DOCS_INDEX.md)
