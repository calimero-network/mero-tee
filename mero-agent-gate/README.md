# mero-agent-gate

Attestation and sealed secret provisioning for the private agent TDX image
([design](../docs/design/private-agents.md), [how it works](../docs/src/content/docs/flows/private-agents.mdx)).

The gate runs beside the agent in the agent image. It proves which image runs,
holds the agent's signing key, and takes the agent's secrets only sealed to this
TD. The agent can then be any program: it reads its secrets from files on the
encrypted disk and signs with the key the gate attested.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | `{"status":"ok","provisioned":bool}`: whether any bundle was written since this start |
| `POST` | `/attest` | `{"nonceB64"}` → a quote whose report data is `nonce ‖ SHA-256("mero-agent-gate/attest/v1" ‖ provisioning_pub ‖ signing_pub)`, and both keys |
| `POST` | `/provision` | An HPKE message sealed to the provisioning key; writes each secret to `secrets/<NAME>` (0600). `403` if no listed provisioner sealed it, `409` if it was sealed to a key from an earlier start |

## Keys

- **Provisioning key**: X25519, generated in memory at every start, never written.
- **Signing key**: Ed25519, generated in the TD on the first boot at
  `$GATE_STATE_DIR/keys/signing.ed25519` (the encrypted disk), mode 0600.

## Provisioning protocol

RFC 9180 HPKE: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305.
`info = "mero-agent-gate/provision/v1" ‖ provisioning_pub`, empty AAD. Plaintext
`{"secrets": {"NAME": "value"}}`; at most 64 secrets of 64 KiB, names
`[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`. Auth mode under a provisioner key listed in
`/etc/mero-agent/provisioners`; Base mode only where
`GATE_ALLOW_UNAUTHENTICATED_PROVISIONING=true`, which `locked-read-only` refuses.

## `mero-agent-provision`

The provisioner's CLI, in this crate:

```bash
mero-agent-provision keygen --out provisioner.key           # prints the public key to list
mero-agent-provision attest --gate http://<agent>:8090 --policy agent-attestation-policy.debug.json
mero-agent-provision provision --gate http://<agent>:8090 --policy agent-attestation-policy.debug.json \
  --key provisioner.key --secrets secrets.json
```

`attest` and `provision` verify the quote (DCAP, nonce, key binding, agent policy,
not a debug TD) before anything is sent. `attest` prints the signing key an
account owner authorizes as the agent's device.

## Configuration

Environment variables are documented in [`src/main.rs`](src/main.rs). The image
bakes them into `/etc/mero-agent/gate.env`; nothing comes from instance metadata.

## Development

```bash
cargo test -p mero-agent-gate
cargo test -p mero-agent-gate --features mock-attestation   # HTTP round trip with mock quotes
```

With `--features mock-attestation`, `GATE_MOCK_ATTESTATION=true` serves mock
quotes and `mero-agent-provision --allow-mock` accepts them. The default build
has neither.
