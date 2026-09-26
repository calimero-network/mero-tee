# mero-kms-phala

KMS service that validates TDX attestations from merod nodes and releases storage encryption keys via Phala dstack.

> **Full documentation**: [Components — mero-kms-phala](https://calimero-network.github.io/mero-tee/components.html)

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/challenge` | Issue nonce challenge for a peer |
| `POST` | `/get-key` | Verify attestation and release encryption key |
| `POST` | `/attest` | KMS self-attestation (quote generation) |

## Quick Start

```bash
cargo build --release
```

## Configuration

See [Config Reference](https://calimero-network.github.io/mero-tee/config-reference.html) for all environment variables.

Key variables: `LISTEN_ADDR`, `DSTACK_SOCKET_PATH`, `MERO_KMS_VERSION`, `MERO_KMS_PROFILE`, `ENFORCE_MEASUREMENT_POLICY`, `MERO_KMS_REQUIRE_SEALED_KEY_RELEASE`.

**Sealed key release.** A key is never meant to cross the wire in the clear: TLS
ends wherever the node's `kms-phala-url` points, which is operator-written metadata,
so a proxy in front of this service could otherwise read every key it releases.
`/attest` with `transportKey: true` returns this service's X25519 transport key
(derived by dstack at `mero-kms/transport/x25519/v1`, so every replica agrees) and
commits to it in the quote. A `/get-key` request carrying `sealToB64` — a one-time
X25519 key its quote and signature commit to — gets the key back as
`sealedKeyB64`/`sealNonceB64` (X25519 → HKDF-SHA256 → AES-256-GCM) instead of `key`.
See `src/sealed.rs`; the format is merod's `kms::sealed`, pinned by shared vectors.

## Development

```bash
ACCEPT_MOCK_ATTESTATION=true cargo run
```

Mock mode skips TDX quote verification and dstack interaction.
