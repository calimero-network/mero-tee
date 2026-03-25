# mero-tee

TEE infrastructure for Calimero: **mero-kms-phala** (Key Management Service for Phala Cloud) and **GCP node-image build** (Packer-based merod node images with TDX attestation).

> **Full documentation**: [Architecture Reference](https://calimero-network.github.io/mero-tee/)

## Components

| Component | Description |
|-----------|-------------|
| **mero-kms-phala** | KMS that validates TDX attestations and releases storage encryption keys to merod nodes running in Phala CVMs |
| **mero-tee/** | GCP Packer build for locked merod node images (debug, debug-read-only, locked-read-only profiles) |
| **attestation-verifier/** | Public web tool for verifying KMS and node attestations via Intel Trust Authority |

## Quick Start

### Build mero-kms-phala

```bash
cargo build --release
```

Requires Rust. Dependencies on `calimero-tee-attestation` and `calimero-server-primitives` via git dependency on [calimero-network/core](https://github.com/calimero-network/core).

### Build GCP Images

See [mero-tee/README.md](mero-tee/README.md). Requires Packer, Ansible, and GCP credentials.

### Verify Release Assets

```bash
# Verify all release trust assets for a tag
scripts/release/verify-release-assets.sh X.Y.Z

# Generate pinned merod KMS config from signed release policy
scripts/policy/generate-merod-kms-phala-attestation-config.sh \
  --profile locked-read-only X.Y.Z https://<kms-url>/
```

## Documentation

All detailed documentation lives in the **[Architecture Reference](https://calimero-network.github.io/mero-tee/)**:

| Topic | Page |
|-------|------|
| High-level architecture & system map | [System Overview](https://calimero-network.github.io/mero-tee/system-overview.html) |
| KMS, node images, attestation verifier | [Components](https://calimero-network.github.io/mero-tee/components.html) |
| Mutual attestation & trust boundaries | [Trust Model](https://calimero-network.github.io/mero-tee/trust-model.html) |
| Challenge/get-key protocol | [Key Release Flow](https://calimero-network.github.io/mero-tee/key-release-flow.html) |
| KMS self-attestation & public verifier | [Attestation Flow](https://calimero-network.github.io/mero-tee/attestation-flow.html) |
| MRTD/RTMR, compose hash, operator verify | [Verification](https://calimero-network.github.io/mero-tee/verification.html) |
| Release classes, CI/CD, pipeline flows | [Release Pipeline](https://calimero-network.github.io/mero-tee/release-pipeline.html) |
| Staging probes, policy promotion, ADRs | [Policy Management](https://calimero-network.github.io/mero-tee/policy-management.html) |
| Phala KMS, GCP nodes, blue-green rollout | [Runbooks](https://calimero-network.github.io/mero-tee/runbooks.html) |
| All environment variables | [Config Reference](https://calimero-network.github.io/mero-tee/config-reference.html) |
| ServiceError variants & HTTP codes | [Error Handling](https://calimero-network.github.io/mero-tee/error-handling.html) |
| TEE terms & definitions | [Glossary](https://calimero-network.github.io/mero-tee/glossary.html) |

## Release Process

1. Merge version bump PR (`Cargo.toml` and `versions.json` aligned)
2. Node release runs first; KMS release waits, then creates draft
3. Human reviews and publishes KMS draft release
4. `update-compatibility-catalog` workflow updates `compatibility-catalog.json`

Two artifact families per version:
- **mero-kms-vX.Y.Z**: KMS binaries, attestation policies, compatibility map, Sigstore signatures
- **mero-tee-vX.Y.Z**: published-mrtds.json, release provenance, SBOM, checksums, Sigstore signatures

## Related Repositories

- [calimero-network/core](https://github.com/calimero-network/core) – merod, node runtime

## License

MIT OR Apache-2.0
