# mero-tee

TEE infrastructure for Calimero: **mero-kms-phala** (Key Management Service for Phala Cloud) and **GCP node-image build** (Packer-based merod node images with TDX attestation).

## Contents

| Component | Description |
|-----------|-------------|
| **mero-kms-phala** | KMS that validates TDX attestations and releases storage encryption keys to merod nodes running in Phala CVM |
| **mero-tee/** | GCP Packer build for locked merod node images (debug, debug-read-only, locked-read-only profiles) |
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
- [Trust, verification, and measurements](docs/release/trust-and-verification.md) – Canonical operator/client guide
- [Release verification output examples](docs/release/verification-examples.md)
- [Migration & Implementation Plan](docs/architecture/migration-plan.md)
- [Architecture & verification boundaries](docs/architecture/trust-boundaries.md)
- [Documentation source index](docs/DOCS_INDEX.md)
- [Architecture graph](docs/DOCS_GRAPH.md) – KMS, mero-tee, regular nodes, and attestation flow
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

See [mero-tee/README.md](mero-tee/README.md). Requires Packer, Ansible, and GCP credentials.

## Releases

- **mero-kms-vX.Y.Z**: KMS binaries and trust assets (including profile policies for `debug`, `debug-read-only`, `locked-read-only`)
- **mero-kms-phala release trust bundle**:
  - `MANIFEST.txt` (canonical inventory + SHA-256 for files inside the bundle),
  - `kms-phala-checksums.txt` (SHA-256 for binary archives),
  - `kms-phala-release-manifest.json` (commit SHA, binary hashes, container digest/tags, `/attest` verification metadata, and per-asset purpose labels such as operator-required/auditor-required),
  - `kms-phala-container-metadata.json` (standalone signed container image metadata for auditors/operators),
  - `kms-phala-attestation-policy.json` (signed KMS attestation allowlists for `core` TEE config),
  - Sigstore keyless signatures/certificates for binary archives, checksums, manifest, and policy (`*.sig`, `*.pem`)
- **Compatibility map artifact**:
  - `kms-phala-compatibility-map.json` (version mapping between KMS and `merod` releases plus profile-specific policy URLs/hashes and profile-specific KMS image tags/digests),
  - Sigstore keyless signature/certificate sidecars (`kms-phala-compatibility-map.json.sig`, `kms-phala-compatibility-map.json.pem`)
- **mero-tee-vX.Y.Z**: `published-mrtds.json` (MRTDs + measurement policy), `release-provenance.json`, SBOM, and `node-image-gcp-checksums.txt`
  - Sigstore signature/certificate sidecars for node-image-gcp trust artifacts (`*.sig`, `*.pem`)

### What signatures prove (and do not prove)

- **Proves**: the artifact was produced by the expected release workflow identity and was not modified in transit.
- **Does NOT prove**: that the source code is non-malicious or that behavior is correct for your use case.
- **Attestation nuance**: runtime attestation (MRTD/RTMR policy checks in `merod`/KMS) can prove measured TEE state matches policy. The build injects `calimero.role=node`, `calimero.profile`, and `calimero.root_hash` into the kernel cmdline (RTMR[2]). At boot, calimero-init extends RTMR[3] with role+profile+root_hash (kernel 6.16+). Each image produces unique measurements; cannot be forged without an identical image. Still does not cover every environment/control-plane risk outside the attested boundary.
- **Operational guidance**: combine signature verification with policy review and quote/reproducibility checks.

Operators use `published-mrtds.json` to verify that deployed GCP nodes match the expected image. See [Trust, verification, and measurements](docs/release/trust-and-verification.md#runtime-node-measurement-verification-mrtdrtmr) for the concrete workflow.

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
scripts/policy/generate-merod-kms-phala-attestation-config.sh --profile locked-read-only X.Y.Z https://<kms-url>/
```

Apply signed policy directly to an existing `merod` node config:

```bash
scripts/policy/apply-merod-kms-phala-attestation-config.sh --profile locked-read-only X.Y.Z https://<kms-url>/ /path/to/merod-home default
```

KMS release flow (draft release + human approval):

- On version bump (Cargo.toml), `release-kms-phala.yaml` builds three KMS profile images (`debug`, `debug-read-only`, `locked-read-only`) as distinct container digests, runs staged probing to collect profile measurements, fetches node policy from the mero-tee release, and creates a **draft** release with all assets.
- The generated KMS release notes include all three profile image references (tag + digest-pinned pull refs) so operators can pin the exact image per cohort.
- Human reviews the draft release (including attestation policy) and publishes when ready.
- Policy is built from probe output + node release assets; no policy files in repo.

Node release flow:

- On version bump (versions.json), `release-node-image-gcp.yaml` builds node images and publishes. Policy is embedded in `published-mrtds.json`.
- KMS and merod fetch policy from each other's releases at runtime (MERO_KMS_VERSION, MERO_TEE_VERSION).
- `post-release-kms-node-e2e.yaml` runs strict KMS↔node compatibility checks after a successful `Release mero-tee` run on `master`, and also evaluates on `master` push. The verify job probes all three KMS profile images and enforces that each profile's runtime measurements match its published profile policy before checking the strict node↔KMS allow/deny matrix.
- A lightweight smoke job also runs on relevant push/PR changes so wiring regressions show up in commit checks.
- Released KMS images are profile-pinned: startup reads the image profile marker and rejects `KMS_POLICY_PROFILE` env overrides, preventing deploy-time profile switching.
- Staging probes are dispatched with unique probe labels so CI can deterministically map each profile to its own probe run artifact.

Recommended release order:

1. Merge version bump PR (Cargo.toml and versions.json aligned).
2. Node release runs first; KMS release waits for it, then creates draft.
3. Human reviews and publishes KMS draft release.
4. `update-compatibility-catalog` workflow runs on release publish and updates `compatibility-catalog.json` (used by MDMA).

## Related Repositories

- [calimero-network/core](https://github.com/calimero-network/core) – merod, node runtime

## License

MIT OR Apache-2.0
