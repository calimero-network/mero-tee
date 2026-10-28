# mero-tee

TEE infrastructure for Calimero: **mero-kms** (the Key Management Service, run as a frozen GCP TDX cluster, one per release) and the **GCP image builds** (mkosi-built merod node, KMS, agent and GPU inference images with TDX attestation).

> **Full documentation**: [Documentation](https://calimero-network.github.io/mero-tee/)

## Components

| Component | Description |
|-----------|-------------|
| **mero-kms** | KMS that validates TDX attestations and releases storage encryption keys to merod nodes. Runs as the frozen, dm-verity-sealed GCP TDX image `merotee-kms-<profile>-<version>`: one 5-replica cluster per release, whose root key exists only in the replicas' memory and is shared only by attested join. See the [design](docs/design/gcp-tdx-kms.md) |
| **mero-tee/** | mkosi build of the merod 1.0 node, KMS, agent and inference images (debug, debug-read-only, locked-read-only profiles) |
| **mero-inference-gate** | The attested TLS front of the private inference image: vLLM on an H100 in a TDX confidential VM, serving a model chosen at deploy time and named, with its weights' digest, in every quote. See the [design](docs/design/private-inference.md) |
| **attestation-verifier/** | Public web tool for verifying KMS and node attestations via Intel Trust Authority |

## Quick Start

### Build mero-kms

```bash
cargo build --release
```

Requires Rust. Dependencies on `calimero-tee-attestation` and `calimero-server-primitives` via git dependency on [calimero-network/core](https://github.com/calimero-network/core).

### Build GCP Images

See [mero-tee/README.md](mero-tee/README.md). Requires mkosi; booting an image needs GCP credentials.

### Verify Release Assets

```bash
# Verify all release trust assets for a tag
scripts/release/verify-release-assets.sh X.Y.Z
```

merod pins the KMS itself: given `MERO_TEE_VERSION` (node metadata
`tee-release-version`) and `--kms-url`, it fetches and verifies the release's
signed `kms-attestation-policy[.<profile>].json` and refuses a KMS whose
MRTD/RTMR0-3 are not in it.

## Documentation

All detailed documentation lives in the **[Documentation](https://calimero-network.github.io/mero-tee/)**:

| Topic | Page |
|-------|------|
| High-level architecture & system map | [System Overview](https://calimero-network.github.io/mero-tee/understand/system-overview/) |
| KMS, node images, attestation verifier | [Components](https://calimero-network.github.io/mero-tee/understand/components/) |
| Mutual attestation & trust boundaries | [Trust Model](https://calimero-network.github.io/mero-tee/understand/trust-model/) |
| Challenge/get-key protocol | [Key Release Flow](https://calimero-network.github.io/mero-tee/flows/key-release/) |
| KMS self-attestation & public verifier | [Attestation Flow](https://calimero-network.github.io/mero-tee/flows/attestation-flow/) |
| MRTD/RTMR, release policy match, operator verify | [Verification](https://calimero-network.github.io/mero-tee/flows/verification/) |
| Release classes, CI/CD, pipeline flows | [Release Pipeline](https://calimero-network.github.io/mero-tee/operate/release-pipeline/) |
| Staging probes, policy promotion, ADRs | [Policy Management](https://calimero-network.github.io/mero-tee/flows/policy-management/) |
| KMS cluster deploy/recovery, GCP nodes, release rollover | [Runbooks](https://calimero-network.github.io/mero-tee/operate/runbooks/) |
| All environment variables | [Config Reference](https://calimero-network.github.io/mero-tee/operate/config-reference/) |
| ServiceError variants & HTTP codes | [Error Handling](https://calimero-network.github.io/mero-tee/operate/error-handling/) |
| TEE terms & definitions | [Glossary](https://calimero-network.github.io/mero-tee/understand/glossary/) |

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
