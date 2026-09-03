# mero-tee

TEE infrastructure for Calimero: **mero-kms-phala** (Key Management Service for Phala Cloud) and **GCP node-image build** (Packer-based merod node images with TDX attestation).

> **Full documentation**: [Documentation](https://calimero-network.github.io/mero-tee/)

## Components

| Component | Description |
|-----------|-------------|
| **mero-kms-phala** | KMS that validates TDX attestations and releases storage encryption keys to merod nodes running in Phala CVMs |
| **mero-tee/** | GCP Packer build for locked merod node images (debug, debug-read-only, locked-read-only profiles) |
| **Fleet HA sidecar** | systemd service baked into ReadOnly fleet node images (`mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2`); waits for merod readiness via `meroctl --output-format json peers`, reads its own PeerId from `config.toml` (`[identity].peer_id`) and its own MRTD from `/sys/class/misc/tdx_guest/measurements/mrtd:sha384`, polls MDMA for group assignments (sending `peer_id` + `mrtd` so MDMA's MRTD-gated `should_join` can match) and joins each via `meroctl tee fleet-join <GROUP_ID>` (group id passed positionally, core >= `0.10.1-rc.27`). Confirms an assignment back to MDMA only when the join command exits 0. See [Fleet HA sidecar lifecycle](#fleet-ha-sidecar-lifecycle) for the join + leave-on-disable reconcile loop. |
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

All detailed documentation lives in the **[Documentation](https://calimero-network.github.io/mero-tee/)**:

| Topic | Page |
|-------|------|
| High-level architecture & system map | [System Overview](https://calimero-network.github.io/mero-tee/understand/system-overview/) |
| KMS, node images, attestation verifier | [Components](https://calimero-network.github.io/mero-tee/understand/components/) |
| Mutual attestation & trust boundaries | [Trust Model](https://calimero-network.github.io/mero-tee/understand/trust-model/) |
| Challenge/get-key protocol | [Key Release Flow](https://calimero-network.github.io/mero-tee/flows/key-release/) |
| KMS self-attestation & public verifier | [Attestation Flow](https://calimero-network.github.io/mero-tee/flows/attestation-flow/) |
| MRTD/RTMR, compose hash, operator verify | [Verification](https://calimero-network.github.io/mero-tee/flows/verification/) |
| Release classes, CI/CD, pipeline flows | [Release Pipeline](https://calimero-network.github.io/mero-tee/operate/release-pipeline/) |
| Staging probes, policy promotion, ADRs | [Policy Management](https://calimero-network.github.io/mero-tee/flows/policy-management/) |
| Phala KMS, GCP nodes, blue-green rollout | [Runbooks](https://calimero-network.github.io/mero-tee/operate/runbooks/) |
| All environment variables | [Config Reference](https://calimero-network.github.io/mero-tee/operate/config-reference/) |
| ServiceError variants & HTTP codes | [Error Handling](https://calimero-network.github.io/mero-tee/operate/error-handling/) |
| TEE terms & definitions | [Glossary](https://calimero-network.github.io/mero-tee/understand/glossary/) |

## Fleet HA sidecar lifecycle

The fleet HA sidecar (`mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2`) runs a
one-second reconcile loop on each ReadOnly TEE fleet node. Every cycle it polls MDMA's
`POST /api/fleet/should-join` with the node's `peer_id` + `mrtd`, then drives merod toward the
namespace set MDMA currently assigns to it.

**Join (converge toward `desired`).** For each assigned namespace not yet confirmed, the sidecar
retries `meroctl tee fleet-join <GROUP_ID>` until core reports `admitted: true`, then `POST`s
`/api/fleet/confirm` back to MDMA. A namespace is only recorded in the local
`fleet-confirmed.json` once both local admission and the MDMA confirm succeed, so a transient
MDMA blip on the confirm step is retried (fleet-join is idempotent in core) rather than lost.

**Delegated execution (the node as a relay).** A fleet node is also the relay a
Calimero Cloud account holder writes through when they run no node at all: they
sign a warrant locally, present it to the node, and the node executes as *their*
principal — the delta is attributed to their account, not the node's. Three
facts have to reach that client and none is derivable off-node, so the sidecar
reports them: its **executor account** (`meroctl account show`, the account a
warrant's `executor` must name), its **relay URL** (from the `relay-url`
instance metadata key — a node cannot derive its own external address), and
whether it holds **`CAN_AUTHOR_ON_BEHALF`** on each namespace (`meroctl group
members get-capabilities`, bit 9). The first two ride the should-join poll; the
third rides `/confirm` and is re-reported whenever it changes, because the
capability is granted by a namespace admin long after admission. Any failure
degrades to "replicates but does not relay" — MDMA then never advertises the
node, so clients are not sent to mint warrants it would refuse. The image opens
exactly one path for this, driven by the single Ansible variable
`fleet_delegated_execution`: a Traefik router exempting
`/admin-api/contexts/<ctx>/intents` from forwardAuth, and merod's
`server.admin.public_intents`. Both from one variable because these nodes run
merod in proxy auth mode, so Traefik is the only gate and a drift between the
two would be silent in the unsafe direction. See [Fleet HA
sidecar](https://calimero-network.github.io/mero-tee/understand/fleet-sidecar/#delegated-execution-the-node-as-a-relay).

**Leave on disable (converge away from dropped namespaces).** When a namespace the node had
previously confirmed (`confirmed`) is no longer in MDMA's assignment set (`desired`) — i.e. HA
disabled, the slot reclaimed, or the node's MRTD no longer trusted — the sidecar self-leaves it
with `meroctl namespace leave <hex_namespace_id>`. That publishes `MemberLeft` at the namespace
root and cascades through every descendant subgroup, so **core** evicts the node from the
namespace and all subgroups and purges its local data and keys. `namespace leave` is idempotent
and non-fatal: leaving a namespace the node already left (or was never a direct member of) is
treated as benign and never aborts the loop.

**Poll-success safety gate.** The entire reconcile — join, leave, and prune — runs **only** after
a successful poll: HTTP 200 with a body that parses as an `{"assignments": [...]}` object. Any
curl error, non-2xx, timeout, or unparseable/wrong-shape 200 body causes the cycle to skip
reconcile and preserve `fleet-confirmed.json` untouched. This is safety-critical: because a
missing assignment now triggers an irreversible leave + key purge, a transient MDMA outage must
never be conflated with "all namespaces disabled" and shred keys on healthy replicas.

> **Note:** this is the mero-tee side — the sidecar is the trigger. The actual eviction and
> data/key purge are performed by **core** in response to `MemberLeft`. The key-deletion half of
> that purge requires core ≥ `0.11.0-rc.6` — the `merodVersion` baked into these node images
> (currently `0.11.0-rc.17`; see `mero-tee/versions.json`) satisfies this — which carries the
> leave→purge, transparent subgroup admission,
> and the Open-subgroup replication fix (core #2809). On older merod the sidecar will still issue
> the leave, but keys may not be purged.

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
