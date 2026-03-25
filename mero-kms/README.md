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

Key variables: `LISTEN_ADDR`, `DSTACK_SOCKET_PATH`, `MERO_KMS_VERSION`, `MERO_KMS_PROFILE`, `ENFORCE_MEASUREMENT_POLICY`.

## Development

```bash
ACCEPT_MOCK_ATTESTATION=true cargo run
```

Mock mode skips TDX quote verification and dstack interaction.
