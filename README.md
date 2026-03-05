# mero-tee

TEE infrastructure for Calimero: **mero-kms-phala** (Key Management Service for Phala Cloud) and **GCP locked image build** (Packer-based merod node images with TDX attestation).

## Contents

| Component | Description |
|-----------|-------------|
| **mero-kms-phala** | KMS that validates TDX attestations and releases storage encryption keys to merod nodes running in Phala CVM |
| **packer/** | GCP Packer build for locked merod node images (debug, debug-read-only, locked-read-only profiles) |
| **Releases** | mero-kms-phala binaries, MRTDs, attestation artifacts, provenance |

## Quick Links

- [Deploy on GCP](docs/deploy-gcp.md) – GCP TDX locked images
- [Deploy on Phala](docs/deploy-phala.md) – Phala Cloud CVM
- [Phala KMS hardening proposal](docs/phala-kms-key-protection-proposal.md)
- [Direct Phala KMS design](docs/phala-direct-kms-design.md)
- [Phala KMS attestation task list (mero-tee)](docs/phala-kms-attestation-task-list.md)
- [KMS blue/green rollout runbook](docs/kms-blue-green-rollout.md)
- [KMS staging probe workflow (Phala)](docs/kms-staging-probe-phala.md)
- [KMS policy promotion workflow (PR)](docs/kms-policy-promotion-pr.md)
- [KMS policy auto pipeline](docs/kms-policy-auto-pipeline.md)
- [Locked-image policy promotion workflow (PR)](docs/locked-image-policy-promotion-pr.md)
- [Verify MRTD](docs/verify-mrtd.md) – Verify nodes run the attested image
- [Release verification output examples](docs/release-verification-examples.md)
- [Migration & Implementation Plan](docs/MIGRATION_PLAN.md)
- [Architecture & Verification](docs/ARCHITECTURE.md)
- [Documentation source index](docs/DOCS_INDEX.md)
- [Release taxonomy](docs/RELEASE_TAXONOMY.md)
- [Security policy](SECURITY.md)
- [Contributing guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Changelog](CHANGELOG.md)
- [mero-kms-phala README](crates/mero-kms-phala/README.md)

## Building mero-kms-phala

```bash
cargo build --release -p mero-kms-phala
```

Requires Rust. Dependencies on `calimero-tee-attestation` and `calimero-server-primitives` are satisfied via git dependency on [calimero-network/core](https://github.com/calimero-network/core).

## Building GCP Images

See [packer/gcp/merod/README.md](packer/gcp/merod/README.md). Requires Packer, Ansible, and GCP credentials.

## Releases

- **mero-kms-phala**: Binaries published per platform
- **mero-kms-phala release trust bundle**:
  - `MANIFEST.txt` (canonical inventory + SHA-256 for files inside the bundle),
  - `mero-kms-phala-checksums.txt` (SHA-256 for binary archives),
  - `mero-kms-phala-release-manifest.json` (commit SHA, binary hashes, container digest/tags, `/attest` verification metadata, policy registry entry path),
  - `mero-kms-phala-attestation-policy.json` (signed KMS attestation allowlists for `core` TEE config),
  - Sigstore keyless signatures/certificates for binary archives, checksums, manifest, and policy (`*.sig`, `*.pem`)
- **Compatibility map artifact**:
  - `mero-tee-compatibility-map.json` (version mapping between KMS and `merod` releases plus pinned policy paths),
  - Sigstore keyless signature/certificate sidecars (`mero-tee-compatibility-map.json.sig`, `mero-tee-compatibility-map.json.pem`)
- **X.Y.Z**: MRTDs (`published-mrtds.json`, `mrtd-*.json`), attestation artifacts, release provenance, and `locked-image-checksums.txt` (same tag as mero-kms-phala)
  - `merod-locked-image-policy.json` (profile-specific allowed MRTD/RTMR policy)
  - Sigstore signature/certificate sidecars for locked-image trust artifacts (`*.sig`, `*.pem`)

### What signatures prove (and do not prove)

- **Proves**: the artifact was produced by the expected release workflow identity and was not modified in transit.
- **Does NOT prove**: that the source code is non-malicious or that behavior is correct for your use case.
- **Operational guidance**: combine signature verification with policy review and quote/reproducibility checks.

Operators use `published-mrtds.json` to verify that deployed GCP nodes match the expected image. See [Verify MRTD](docs/verify-mrtd.md) for step-by-step instructions.

Verify KMS release assets:

```bash
scripts/verify_mero_kms_release_assets.sh X.Y.Z
```

Verify all available release trust assets for a tag (KMS and/or locked-image):

```bash
scripts/verify_all_release_assets.sh X.Y.Z
```

Generate a pinned `core` TEE config snippet from signed release policy:

```bash
scripts/generate_merod_kms_attestation_config.sh X.Y.Z https://<kms-url>/
```

Apply signed policy directly to an existing `merod` node config:

```bash
scripts/apply_merod_kms_attestation_config.sh X.Y.Z https://<kms-url>/ /path/to/merod-home default
```

Collect candidate KMS allowlists automatically from a staged Phala deployment:

- Run GitHub Actions workflow `.github/workflows/kms_staging_probe_phala.yaml`
- Requires repository secrets: `PHALA_CLOUD_API_KEY`, `ITA_API_KEY`
- By default, workflow resolves image from latest release tag; optional `kms_image` override must be pinned and expose `/attest` (do not use container `:latest`)
- Produces policy candidate artifacts for PR promotion

Promote staged candidates into a reviewable, versioned policy PR:

- Run GitHub Actions workflow `.github/workflows/kms_policy_promotion_pr.yaml`
- Input the probe run ID and target release tag
- Workflow updates `policies/mero-kms-phala/<tag>.json` + `index.json` and opens a PR
  (or prints a manual PR compare URL if Actions PR creation is disabled)
- `index.json` keeps a historical list of versioned policy entries (with SHA-256)
- Automatic option: `.github/workflows/kms_policy_auto_pipeline.yaml` dispatches
  probe + promotion workflows after version bumps merged to `master`

Release automation reads the policy registry directly (`policies/mero-kms-phala`)
for the target crate version, so version bump + promoted policy stay aligned.

Locked-image policy history is tracked under `policies/merod-locked-image` and
can be promoted from release assets using
`.github/workflows/locked_image_policy_promotion_pr.yaml` (auto-dispatched by
`gcp_locked_image_build.yaml` after release publish, with manual fallback).

Recommended release order:

1. Merge version bump PR for the target release tag.
2. Auto policy pipeline dispatches probe + promotion PR (or run those manually).
3. Review and merge policy PR for the same release tag.
4. Release workflow publishes signed artifacts from the merged policy registry entry.

## Related Repositories

- [calimero-network/core](https://github.com/calimero-network/core) – merod, node runtime

## License

MIT OR Apache-2.0
