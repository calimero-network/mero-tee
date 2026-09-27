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
| `GET` | `/health` | `{"status":"alive","service":"mero-kms","clusterRootReady":bool}`, plus `lastJoinError` (why this replica's last join failed) and `lastJoinRefusal` (the last join it refused) once there is one |
| `POST` | `/challenge` | Issue a challenge for a peer (503 until the replica holds the root) |
| `POST` | `/get-key` | Verify the challenge, signature and attestation, and release the node's key |
| `POST` | `/attest` | KMS self-attestation: a quote over the caller's nonce, optionally reporting the transport key |
| `POST` | `/cluster/nonce` | Single-use nonce for a replica joining the cluster |
| `POST` | `/cluster/join` | Give the root to a replica with exactly this replica's measurements |

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
| `MERO_KMS_JOIN_RETRY_SECS` | `10` | Pause between rounds of join attempts |
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

## Development

```bash
ACCEPT_MOCK_ATTESTATION=true MERO_KMS_BOOTSTRAP=true \
  cargo run -p mero-kms --features mock-attestation
```

Mock mode (only compiled with the default-off `mock-attestation` feature) takes mock
quotes of itself instead of real TDX quotes, and accepts mock quotes from nodes.
