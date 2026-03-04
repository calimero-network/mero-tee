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
- [Verify MRTD](docs/verify-mrtd.md) – Verify nodes run the attested image
- [Migration & Implementation Plan](docs/MIGRATION_PLAN.md)
- [Architecture & Verification](docs/ARCHITECTURE.md)
- [Security (no secrets)](SECURITY.md)
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
  - `mero-kms-phala-checksums.txt` (SHA-256 for binary archives),
  - `mero-kms-phala-release-manifest.json` (commit SHA, binary hashes, container digest/tags, `/attest` verification metadata),
  - `mero-kms-phala-attestation-policy.json` (signed KMS attestation allowlists for `core` TEE config),
  - Sigstore keyless signatures/certificates for binary archives, checksums, manifest, and policy (`*.sig`, `*.pem`)
- **X.Y.Z**: MRTDs (`published-mrtds.json`, `mrtd-*.json`), attestation artifacts, release provenance, and `locked-image-checksums.txt` (same tag as mero-kms-phala)
  - Sigstore signature/certificate sidecars for locked-image trust artifacts (`*.sig`, `*.pem`)

Operators use `published-mrtds.json` to verify that deployed GCP nodes match the expected image. See [Verify MRTD](docs/verify-mrtd.md) for step-by-step instructions.

Verify KMS release assets:

```bash
scripts/verify_mero_kms_release_assets.sh X.Y.Z
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
- Produces copy/paste-ready `MERO_KMS_ALLOWED_*_JSON` values and probe artifacts

Promote staged candidates into a reviewable, versioned policy PR:

- Run GitHub Actions workflow `.github/workflows/kms_policy_promotion_pr.yaml`
- Input the probe run ID and target release tag
- Workflow updates `policies/mero-kms-phala/<tag>.json` + `index.json` and opens a PR
  (or prints a manual PR compare URL if Actions PR creation is disabled)

## Related Repositories

- [calimero-network/core](https://github.com/calimero-network/core) – merod, node runtime

## License

MIT OR Apache-2.0
