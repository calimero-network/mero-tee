# mero-kms

Key management service for merod nodes running in TDX. It validates a node's TDX
attestation and releases that node's storage encryption key.

mero-kms runs as a cluster of plain TDX VMs, one cluster per release. Keys derive
(HKDF-SHA256) from a random **root** that exists only in the replicas' memory: the
first replica generates it, and every other replica gets it from a peer whose quote
carries exactly its own MRTD and RTMR0–3 ("same as me"; both sides attest). Nothing
writes the root to disk, and replicas never restart in place: a dead replica is
replaced by a new VM that joins its peers. See the [design](../docs/design/gcp-tdx-kms.md).

> **Full documentation**: [Components — mero-kms](https://calimero-network.github.io/mero-tee/components.html)

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | `{"status":"alive","service":"mero-kms","clusterRootReady":bool,"countersReady":bool}`, plus `lastJoinError` while a joining replica has no root and `lastJoinRefusal` once a replica has refused a join |
| `POST` | `/challenge` | Issue a challenge for a peer (503 until the replica holds the root) |
| `POST` | `/get-key` | Verify the challenge, signature and attestation, and release the node's key |
| `POST` | `/attest` | KMS self-attestation: a quote over the caller's nonce, optionally reporting the transport key (`transportKey`) and the CCEL event log (`eventLog`) |
| `POST` | `/cluster/nonce` | Single-use nonce for a replica joining the cluster |
| `POST` | `/cluster/join` | Give the root to a replica with exactly this replica's measurements |
| `POST` | `/rollback/raise` | Raise a node's rollback counter (MACed under the session key its v2 release sealed) |
| `POST` | `/rollback/reset` | Force a node's counter down to its store's (merod `--accept-rollback`); one epoch up |
| `POST` | `/cluster/counters/read` | Another replica reads counters (MACed under a root-derived key) |
| `POST` | `/cluster/counters/merge` | Another replica writes counters (same) |

Every replica sits behind one load-balanced URL, with no stickiness and no shared
storage. The `challengeId` `/challenge` returns is therefore self-contained: 16
random bytes and its expiry, and its nonce is an HMAC-SHA256 over the ID and the
peer id, keyed by a key HKDF'd from the root under a salt of its own. Any replica of
the cluster recomputes the nonce; each replica refuses a challenge it already
accepted until it expires. See `src/stateless_challenge.rs`.

## Quick Start

```bash
cargo build --release -p mero-kms
```

## Configuration

Everything is read from the environment, which the image bakes in (`kms.env`), so it
is part of the image's measurements. The node allowlist (`ALLOWED_*`) always comes
from there; with measurement enforcement on, startup fails unless every register has
at least one allowed value. See `src/config/mod.rs` for the full table.

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `0.0.0.0:8080` | HTTP listen address |
| `MERO_KMS_PROFILE` | `locked-read-only` | Profile cohort; part of every key path. Must match `/etc/mero-kms/image-profile` when present |
| `KMS_POLICY_PROFILE` | — | Deprecated alias for `MERO_KMS_PROFILE` |
| `KEY_NAMESPACE_PREFIX` | `merod/storage` | Key paths are `{prefix}/{profile}/{peerId}` |
| `ENFORCE_MEASUREMENT_POLICY` | `true` | Enforce the node allowlist |
| `ALLOWED_TCB_STATUSES` | `uptodate` | Allowed TCB statuses, for nodes and for joining replicas |
| `ALLOWED_MRTD`, `ALLOWED_RTMR0`…`ALLOWED_RTMR3` | — | Comma-separated node measurements (96 hex chars each) |
| `MERO_KMS_REQUIRE_SEALED_KEY_RELEASE` | `true` | Refuse `/get-key` requests without `sealToB64` |
| `MERO_KMS_BOOTSTRAP` | `false` | Generate the cluster root (exactly one replica, once) |
| `MERO_KMS_PEERS` | — | Comma-separated base URLs of replicas to join from; required unless bootstrapping |
| `MERO_KMS_JOIN_RETRY_SECS` | `10` | Pause between rounds of join attempts (and of counter syncs) |
| `MERO_KMS_REPLICAS` | `1` | Replicas in the cluster; a rollback counter is acknowledged once a majority hold it. More than 1 needs `MERO_KMS_PEERS` (the other replicas) on every replica, the bootstrapping one included. Bake it into `kms.env` |
| `CHALLENGE_TTL_SECS` | `60` | Lifetime of a challenge |
| `MAX_CONSUMED_CHALLENGES` | `10000` | Used, unexpired challenges one replica remembers; `/get-key` answers 429 when full |
| `CORS_ALLOWED_ORIGINS` | — | Comma-separated CORS origins; CORS is off when unset |
| `ACCEPT_MOCK_ATTESTATION` | `false` | Only with the `mock-attestation` feature: accept mock quotes. Never in production |

On a KMS VM, `kms-init.sh` sets `MERO_KMS_BOOTSTRAP` and `MERO_KMS_PEERS` from the
`kms-bootstrap` and `kms-peers` instance metadata.

**Sealed key release.** A key is never meant to cross the wire in the clear: TLS
ends wherever the node's `kms-url` points, which is operator-written metadata, so a
proxy in front of this service could otherwise read every key it releases.
`/attest` with `transportKey: true` returns the cluster's X25519 transport key
(derived from the root at `mero-kms/transport/x25519/v1`, so every replica agrees)
and commits to it in the quote. A `/get-key` request carrying `sealToB64` — a
one-time X25519 key its quote and signature commit to — gets the key back as
`sealedKeyB64`/`sealNonceB64` (X25519 → HKDF-SHA256 → AES-256-GCM) instead of `key`.
A request without `sealToB64` is refused unless `MERO_KMS_REQUIRE_SEALED_KEY_RELEASE=false`.
See `src/sealed.rs`; the format is merod's `kms::sealed`, pinned by shared vectors.

**Rollback counters.** A host can restart a node on an older copy of its disk,
and sealing hides a copy's content, not its age. So mero-kms keeps, per cluster key
path, an `epoch` (forced rollbacks) and per node id an entry `(generation, mark)`
the node also keeps in its sealed store and raises about once a second; merod
refuses to start on a store below it (core `docs/specs/rollback-protection.md`).

- `/attest` with `transportKey` and `capabilities: true` answers
  `capabilities: ["rollback/v1"]` and binds `SHA-256("mero-kms/attest-transport-key/v2"
  ‖ binding ‖ transport key ‖ "rollback/v1")`; without `capabilities` it is unchanged.
- `/get-key` with `rollbackNodeId` (needs `sealToB64`): the quote binds
  `SHA-256("mero-kms/sealed-get-key/v2" ‖ sealTo ‖ peerId ‖ nodeId as 8 bytes BE)`,
  the signed payload gains `rollbackNodeId`, and `sealedKeyB64` holds, sealed under
  the domain `mero-kms/sealed-key/v2`, the JSON `{keyHex, epoch, generation, mark?,
  sessionIdB64, sessionKeyHex}` (`mark` absent while there is no entry). Node
  role only.
- The session key is `HKDF-SHA256(root, salt "mero-kms/tdx-root/rollback-session/v1",
  info keyPath "\n" nodeId "\n" hex(sessionId))`: any replica recomputes it, none
  stores it. `/rollback/raise` and `/rollback/reset` take `{peerId, nodeId,
  sessionIdB64, generation, mark, nonceB64, macB64}`, MACed (HMAC-SHA256) over
  `domain ‖ peerId ‖ "\n" ‖ nodeId ‖ sessionId ‖ generation ‖ mark ‖ nonce` (integers
  8 bytes BE; domains `mero-kms/rollback-raise/v1`, `mero-kms/rollback-reset/v1`),
  and answer `{epoch, generation, mark, macB64}` MACed over
  `"mero-kms/rollback-ack/v1" ‖ nonce ‖ epoch ‖ generation ‖ mark`. A raise only
  moves an entry up; a reset sets it to `(epoch + 1, mark)`.
- **Replication.** Counters live in memory, like the root. A write is answered
  once a majority of `MERO_KMS_REPLICAS` hold it; a read merges a majority's
  views. Replicas MAC counter messages with a root-derived key and answer with a
  random replica id, so only distinct replicas of this cluster count. A joiner
  answers no counter request (503 `counters_unavailable`) until it has merged a
  majority of ready replicas' counters. While a cluster is brought up, the
  bootstrap replica starts ready in *genesis*, and a joiner that hears only empty
  genesis replicas joins it; genesis ends once one round hears every replica
  ready (needed before the first write), and 10 minutes after the root was made.
  Limits: `MAX_COUNTER_CLUSTERS` (10 000), `MAX_COUNTER_NODES_PER_CLUSTER` (1024),
  `MAX_REPLICAS` (15).
- **Not yet in the image:** `kms.env` does not set `MERO_KMS_REPLICAS`, so each
  replica keeps counters of its own, which a load balancer makes meaningless. Set
  it (and `kms-peers` on the bootstrap replica) before nodes rely on counters.
- What `/rollback/*` logs: raises at DEBUG, a forced rollback as `Forced a
  rollback` (WARN) with the peer, node, mark and epoch; refusals as `Refused a
  rollback call: <reason>`. Never the session key.

## Logging

The journal leaves the replica. With `logs-endpoint` in its instance metadata,
`kms-init` starts vector, which ships `mero-kms-init`, `mero-kms`, `vector` and
`vmagent` to VictoriaLogs. `metrics-endpoint` does the same for vmagent and
node_exporter host metrics, which listen on loopback only. The labels are
`instance_name="mero-kms"` (logs) and `instance_type="mero-kms"` (metrics),
so KMS data never mixes with the fleet's. Metadata is operator-written, so
anything logged must be safe for an operator to read. The rules:

- **What `/get-key` logs:** `Received key release request`, then either
  `Key derived successfully` or `Refused a key release: <reason>` (the
  `ServiceError` message), with the peer ID. Joins log `Joined the cluster`,
  `Cluster join failed: …` (joiner) and `Refused a cluster join: …` (giver).
  The KMS dashboard counts these lines.
- **Log peers, measurements and outcomes; never key material.** Nothing derived
  from the root (node keys, the challenge key, the transport key), the root
  itself, X25519 secrets, shared secrets or a sealing buffer may reach a log,
  an error message or a `/health` field. Public values are fine: peer IDs,
  public keys, challenge IDs, nonces, quote hashes, MRTD/RTMR0–3, TCB status,
  URLs, status codes.
- **A secret-holding type gets no `Debug` or `Display`, or one that redacts.**
  `Root` and `TransportKey` have none, so logging one does not compile.
  `GetKeyResponse` redacts `key`. Note that `Zeroizing<T>` *prints* its
  contents: never format one.
- **Error messages for crypto failures are static strings**, never a value.
- **`RUST_LOG=info` is baked** into `kms.env` and measured; metadata cannot
  change it. tower-http's `TraceLayer` records method, URI, status and latency
  at DEBUG, and never headers or bodies. Every secret travels in a POST body.
- **Caller input is validated before it is logged**: a peer ID with leading or
  trailing whitespace is refused, so a newline cannot forge a log line.

## Development

```bash
ACCEPT_MOCK_ATTESTATION=true MERO_KMS_BOOTSTRAP=true \
  cargo run -p mero-kms --features mock-attestation
```

Mock mode (only compiled with the default-off `mock-attestation` feature) takes mock
quotes of itself instead of real TDX quotes, and accepts mock quotes from nodes.
