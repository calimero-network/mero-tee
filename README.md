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
- **X.Y.Z**: MRTDs (`published-mrtds.json`, `mrtd-*.json`), attestation artifacts, release provenance, and Sigstore signature/certificate sidecars (`*.sig`, `*.pem`) (same tag as mero-kms-phala)

Operators use `published-mrtds.json` to verify that deployed GCP nodes match the expected image. See [Verify MRTD](docs/verify-mrtd.md) for step-by-step instructions.

## Related Repositories

- [calimero-network/core](https://github.com/calimero-network/core) – merod, node runtime

## License

MIT OR Apache-2.0
