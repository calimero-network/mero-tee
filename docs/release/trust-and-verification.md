# Trust & Verification

This page is the single entry point for how trust is established for released artifacts in `mero-tee`.

## Scope

This repository publishes two trust-asset families per release tag:

1. **KMS release assets** on tag `mero-kms-vX.Y.Z` (`mero-kms-phala` binaries + policy/manifest/signatures)
2. **node-image-gcp assets** on tag `mero-tee-vX.Y.Z` (MRTDs, policy, release provenance, signatures)

These map to two deployment lanes with different responsibilities:

- **Phala KMS lane** (operate `mero-kms-phala`): [../runbooks/platforms/phala-kms.md](../runbooks/platforms/phala-kms.md)
- **GCP node lane** (deploy locked `merod` image): [../runbooks/platforms/gcp-merod.md](../runbooks/platforms/gcp-merod.md)

## What signatures prove (and do not prove)

- **Proves**: an artifact was produced by the expected GitHub Actions workflow identity and was not modified after signing.
- **Does not prove**: source code quality, absence of vulnerabilities, or fitness for your deployment model.

Use signatures together with:

- policy review (`published-mrtds.json`, `kms-phala-attestation-policy.json`)
- compatibility checks (`kms-phala-compatibility-map.json` + node/KMS policy assets)
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

## Verification direction matrix (who proves what to whom)

This is the canonical direction of trust checks:

| Verifier | Subject being verified | Evidence/API | Required check before proceeding |
|---|---|---|---|
| `merod` (client node) | KMS (`mero-kms-phala`) | `POST /attest` quote + report data | Verify quote cryptographically, verify nonce/binding, and enforce KMS TCB + MRTD + RTMR0..3 allowlists |
| KMS (`mero-kms-phala`) | `merod` (requesting node) | `POST /challenge` + `POST /get-key` quote + peer signature | Verify peer identity/signature/challenge freshness, verify quote cryptographically, and enforce node TCB + MRTD + RTMR0..3 allowlists |
| Operator CI/acceptance | Release artifacts and policy metadata | Sigstore sidecars + release manifests/checksums | Verify workflow identity, checksums, and compatibility map before rollout |

If any verification step fails, key release or rollout approval must fail closed.

## Profile/KMS compatibility assumptions

`node-image-gcp` currently has three profiles: `debug`, `debug-read-only`, `locked-read-only`.

Recommended trust posture:

| Node profile | Typical use | KMS policy expectation |
|---|---|---|
| `debug` | local/dev investigations only | separate non-production KMS policy/lane; never shared with production keys |
| `debug-read-only` | pre-production hardening/tests | separate non-production KMS policy/lane; never shared with production keys |
| `locked-read-only` | production baseline | production KMS policy allowlist should be pinned to this profile's measurements |

Practical rule for operators: **debug images should only talk to debug/non-production KMS policy cohorts**.

## Check release-level KMS↔node mapping

Before rollout, verify compatibility artifacts for the same release version:

```bash
TAG=2.1.10
BASE="https://github.com/calimero-network/mero-tee/releases/download/mero-kms-v${TAG}"
curl -fsSL "${BASE}/kms-phala-compatibility-map.json" | jq '.compatibility'
```

Confirm:

- `kms_tag` is `mero-kms-v${TAG}`
- `node_image_tag` points to the intended `mero-tee-v...` release
- `kms_policy_url` and `node_policy_url` resolve to the reviewed signed assets

## Related docs

- [TEE verification for beginners](verification-beginner.md)
- [Platform runbooks](../runbooks/platforms/README.md)
- [Verify MRTD](../runbooks/operations/verify-mrtd.md)
- [Release verification examples](verification-examples.md)
- [Architecture](../architecture/trust-boundaries.md)
- [Release taxonomy](taxonomy.md)
- [Documentation source index](../DOCS_INDEX.md)
