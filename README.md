# mero-tee

**The trust layer behind Calimero: the hardware images and key service that make "nobody can read your data, not even us" true, and checkable.**

[Calimero](https://github.com/calimero-network/core) is an app backend, like
Firebase, that runs every app inside attested Intel TDX confidential VMs. This
repository builds what those VMs boot and how they get their keys:

- **The images.** The merod node, mero-kms and private-inference images for GCP
  TDX, built reproducibly with mkosi and sealed with dm-verity. Their
  measurements (MRTD and RTMR0-3) are published with every release.
- **The keys.** mero-kms hands a node its disk key only after checking the
  node's attestation against those published measurements. A node running
  anything else, or a copied disk, gets nothing.
- **The proof.** Every release is signed with Sigstore, so clients (mero-js,
  calimero-client-py, meroctl) and anyone else can check a node against it. The
  [attestation verifier](attestation-verifier/) does it in a browser.

> **Full documentation**: [calimero-network.github.io/mero-tee](https://calimero-network.github.io/mero-tee/)

## Components

| Component | Description |
|-----------|-------------|
| **mero-kms** | KMS that validates TDX attestations and releases storage encryption keys to merod nodes. Runs as the frozen, dm-verity-sealed GCP TDX image `merotee-kms-<profile>-<version>`: one 5-replica cluster per release, whose root key exists only in the replicas' memory and is shared only by attested join. See the [design](docs/design/gcp-tdx-kms.md) |
| **mero-tee/** | mkosi build of the merod 1.0 node, KMS and inference images (debug, debug-read-only, locked-read-only profiles) |
| **mero-inference-gate** | The attested TLS front of the private inference image: vLLM on an H100 in a TDX confidential VM, serving a model chosen at deploy time and named, with its weights' digest, in every quote. See the [design](docs/design/private-inference.md) |
| **attestation-verifier/** | Public web tool for verifying KMS and node attestations via Intel Trust Authority |

## Quick Start

### Build mero-kms

```bash
cargo build --release
```

Requires Rust. Depends on `calimero-tee-attestation` via a git dependency on [calimero-network/core](https://github.com/calimero-network/core).

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

1. Merge version bump PR (`Cargo.toml` and `mero-tee/versions.json` aligned)
2. Node release runs first; KMS release waits, then creates draft
3. Human reviews and publishes KMS draft release
4. `update-compatibility-catalog` workflow updates `compatibility-catalog.json`

Two artifact families per version:
- **mero-kms-vX.Y.Z**: KMS binaries, attestation policies, compatibility map, Sigstore signatures
- **mero-tee-vX.Y.Z**: published-mrtds.json, release provenance, SBOM, checksums, Sigstore signatures

## Related Repositories

| Repo | What it is |
| --- | --- |
| [core](https://github.com/calimero-network/core) | merod, meroctl, the app SDK: the platform these images run |
| [mero-js](https://github.com/calimero-network/mero-js) · [calimero-client-py](https://github.com/calimero-network/calimero-client-py) | Clients that verify a node against these releases before sending anything |

## License

MIT OR Apache-2.0
