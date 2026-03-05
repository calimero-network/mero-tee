# mero-tee

TEE infrastructure for Calimero: **mero-kms-phala** (Key Management Service for Phala Cloud) and **GCP node-image build** (Packer-based merod node images with TDX attestation).

## Contents

| Component | Description |
|-----------|-------------|
| **mero-kms-phala** | KMS that validates TDX attestations and releases storage encryption keys to merod nodes running in Phala CVM |
| **node-image-gcp/** | GCP Packer build for locked merod node images (debug, debug-read-only, locked-read-only profiles) |
| **Releases** | mero-kms-phala binaries, MRTDs, attestation artifacts, provenance |

## Quick Links

- [Platform runbooks](docs/runbooks/platforms/README.md) – deployment lanes by responsibility
- [Phala KMS lane](docs/runbooks/platforms/phala-kms.md) – deploy/operate `mero-kms-phala` (KMS plane)
- [GCP node lane](docs/runbooks/platforms/gcp-merod.md) – deploy locked `merod` images (node plane)
- [Phala KMS hardening proposal](docs/architecture/phala-kms-key-protection-proposal.md)
- [Direct Phala KMS design](docs/architecture/phala-direct-kms-design.md)
- [Phala KMS attestation task list (mero-tee)](docs/policies/kms-phala-attestation-task-list.md)
- [KMS blue/green rollout runbook](docs/runbooks/operations/kms-blue-green-rollout.md)
- [KMS staging probe workflow (Phala)](docs/policies/kms-phala-staging-probe.md)
- [KMS policy promotion workflow (PR)](docs/policies/kms-phala-policy-promotion.md)
- [KMS policy auto pipeline](docs/policies/kms-phala-policy-auto-pipeline.md)
- [node-image-gcp policy promotion workflow (PR)](docs/policies/node-image-gcp-policy-promotion.md)
- [Verify MRTD](docs/runbooks/operations/verify-mrtd.md) – Verify nodes run the attested image
- [Release verification output examples](docs/release/verification-examples.md)
- [Migration & Implementation Plan](docs/architecture/migration-plan.md)
- [Architecture & verification boundaries](docs/architecture/trust-boundaries.md)
- [TEE verification for beginners](docs/release/verification-beginner.md)
- [Documentation source index](docs/DOCS_INDEX.md)
- [Docs navigation/anchor map (maintainers)](docs/DOCS_NAVIGATION_MAP.md)
- [Release pipeline sequence diagrams](docs/release/pipeline-sequence-diagrams.md)
- [Release taxonomy](docs/release/taxonomy.md)
- [Repo restructure proposal](docs/REPO_RESTRUCTURE_PROPOSAL.md)
- [Security policy](SECURITY.md)
- [Contributing guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Changelog](CHANGELOG.md)
- [mero-kms-phala README](mero-kms/README.md)

## Building mero-kms-phala

```bash
cargo build --release
```

Requires Rust. Dependencies on `calimero-tee-attestation` and `calimero-server-primitives` are satisfied via git dependency on [calimero-network/core](https://github.com/calimero-network/core).

## Building GCP Images

See [node-image-gcp/README.md](node-image-gcp/README.md). Requires Packer, Ansible, and GCP credentials.

## Releases

- **mero-kms-phala**: Binaries published per platform
- **mero-kms-phala release trust bundle**:
  - `MANIFEST.txt` (canonical inventory + SHA-256 for files inside the bundle),
  - `kms-phala-checksums.txt` (SHA-256 for binary archives),
  - `kms-phala-release-manifest.json` (commit SHA, binary hashes, container digest/tags, `/attest` verification metadata, policy registry entry path, and per-asset purpose labels such as operator-required/auditor-required),
  - `kms-phala-container-metadata.json` (standalone signed container image metadata for auditors/operators),
  - `kms-phala-attestation-policy.json` (signed KMS attestation allowlists for `core` TEE config),
  - Sigstore keyless signatures/certificates for binary archives, checksums, manifest, and policy (`*.sig`, `*.pem`)
- **Compatibility map artifact**:
  - `kms-phala-compatibility-map.json` (version mapping between KMS and `merod` releases plus pinned policy paths),
  - Sigstore keyless signature/certificate sidecars (`kms-phala-compatibility-map.json.sig`, `kms-phala-compatibility-map.json.pem`)
- **node-image-gcp-vX.Y.Z**: MRTDs (`published-mrtds.json`, `mrtd-*.json`), attestation artifacts, release provenance, and `node-image-gcp-checksums.txt`
  - `node-image-gcp-policy.json` (profile-specific allowed MRTD/RTMR policy)
  - Sigstore signature/certificate sidecars for node-image-gcp trust artifacts (`*.sig`, `*.pem`)

### What signatures prove (and do not prove)

- **Proves**: the artifact was produced by the expected release workflow identity and was not modified in transit.
- **Does NOT prove**: that the source code is non-malicious or that behavior is correct for your use case.
- **Attestation nuance**: runtime attestation (MRTD/RTMR policy checks in `merod`/KMS) can prove measured TEE state matches policy, but still does not cover every environment/control-plane risk outside the attested boundary.
- **Operational guidance**: combine signature verification with policy review and quote/reproducibility checks.

Operators use `published-mrtds.json` to verify that deployed GCP nodes match the expected image. See [Verify MRTD](docs/runbooks/operations/verify-mrtd.md) for step-by-step instructions.

For a consolidated trust model and verification entry point, see [Trust & Verification](docs/release/trust-and-verification.md).

Verify KMS release assets:

```bash
scripts/release/verify-kms-phala-release-assets.sh X.Y.Z
```

Verify all available release trust assets for a tag (KMS and/or node-image-gcp):

```bash
scripts/release/verify-release-assets.sh X.Y.Z
```

Need an explicit artifact list for air-gapped or bandwidth-limited environments? See [Minimal download sets](docs/release/minimal-download-sets.md) for quick-verify vs full-audit bundles.

Generate a pinned `core` TEE config snippet from signed release policy:

```bash
scripts/policy/generate-merod-kms-phala-attestation-config.sh X.Y.Z https://<kms-url>/
```

Apply signed policy directly to an existing `merod` node config:

```bash
scripts/policy/apply-merod-kms-phala-attestation-config.sh X.Y.Z https://<kms-url>/ /path/to/merod-home default
```

Collect candidate KMS allowlists automatically from a staged Phala deployment:

- Run GitHub Actions workflow `.github/workflows/kms-phala-staging-probe.yaml`
- Requires repository secrets: `PHALA_CLOUD_API_KEY`, `ITA_API_KEY`
- By default, workflow resolves image from latest release tag; optional `kms_image` override must be pinned and expose `/attest` (do not use container `:latest`)
- Produces policy candidate artifacts for PR promotion

Promote staged candidates into a reviewable, versioned policy PR:

- Run GitHub Actions workflow `.github/workflows/kms-phala-policy-promotion-pr.yaml`
- Input the probe run ID and target release tag
- Workflow updates `policies/kms-phala/<tag>.json` + `index.json` and opens a PR
  (or prints a manual PR compare URL if Actions PR creation is disabled)
- `index.json` keeps a historical list of versioned policy entries (with SHA-256)
- Automatic option: `.github/workflows/kms-phala-policy-auto-pipeline.yaml` dispatches
  probe + promotion workflows after version bumps merged to `master`

Release automation reads the policy registry directly (`policies/kms-phala`)
for the target package version, so version bump + promoted policy stay aligned.

node-image-gcp policy history is tracked under `policies/node-image-gcp` and
can be promoted from release assets using
`.github/workflows/node-image-gcp-policy-promotion-pr.yaml` (auto-dispatched by
`release-node-image-gcp.yaml` after release publish, with manual fallback).

Recommended release order:

1. Merge version bump PR for the target release tag.
2. Auto policy pipeline dispatches probe + promotion PR (or run those manually).
3. Review and merge policy PR for the same release tag.
4. Release workflow publishes signed artifacts from the merged policy registry entry.

## Related Repositories

- [calimero-network/core](https://github.com/calimero-network/core) – merod, node runtime

## License

MIT OR Apache-2.0
