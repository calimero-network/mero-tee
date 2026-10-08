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
| `GET` | `/health` | `{"status":"ok","provisioned":bool,"claimed":bool}`: whether any bundle was written since this start, and whether an owner claimed the agent |
| `POST` | `/attest` | `{"nonceB64"}` → a quote whose report data is `nonce ‖ SHA-256("mero-agent-gate/attest/v2" ‖ provisioning_pub ‖ signing_pub ‖ owner_pub)`, and the keys. `owner_pub` is 32 zero bytes, and `ownerPublicKeyB64` null, while unclaimed |
| `POST` | `/provision` | An HPKE message sealed to the provisioning key, with its sender's key; writes each secret to `secrets/<NAME>` (0640, root:`GATE_SHARE_GROUP`; 0600 without a group) and answers `{"written","claimed"}`. `403` if another key claimed the agent or the sender did not seal it, `409` if it was sealed to a key from an earlier start |

## Keys

- **Provisioning key**: X25519, generated in memory at every start, never written.
- **Signing key**: Ed25519, generated in the TD on the first boot at
  `$GATE_STATE_DIR/keys/signing.ed25519` (the encrypted disk), mode 0640 root:`GATE_SHARE_GROUP` (0600 without one). The gate runs as root, which configfs-tsm quotes need; the agent reads through its group.
- **Owner key**: the X25519 public key that claimed the agent, at
  `$GATE_STATE_DIR/keys/owner.x25519`. Written once, never replaced: a new
  owner means a new disk, which means a new signing key.

## Provisioning protocol

RFC 9180 HPKE: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305.
`info = "mero-agent-gate/provision/v1" ‖ provisioning_pub`, empty AAD. Plaintext
`{"secrets": {"NAME": "value"}}`; at most 64 secrets of 64 KiB, names
`[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`. Always Auth mode, under the sender's X25519 key.

**Owner claim.** Nobody is baked in as allowed to provision, so neither who
builds the image nor who runs the VM chooses who sets its secrets. The first
bundle that opens under its sender's key and is valid claims the agent for that
key: the gate stores it on the encrypted disk before writing any secret, and
binds it into every later quote. From then on only that key can provision.
Before sending anything, `mero-agent-provision` refuses an agent whose quote
binds another owner, since that owner could read what it is given; after
provisioning, it attests again and checks the fresh quote binds its own key.

Whoever reaches a fresh agent first can claim it. That race is visible, not
silent: the claimant's key is in every quote, so the real owner sees "not
yours", sends nothing, does not authorize its signing key, and replaces the
VM. Launch the agent and claim it in one step, before announcing its address.

## `mero-agent-provision`

The provisioner's CLI, in this crate:

```bash
mero-agent-provision keygen --out owner.key                 # keep it; prints the public key
mero-agent-provision attest --gate http://<agent>:8090 --policy agent-attestation-policy.debug.json \
  --key owner.key                                           # fails unless unclaimed or yours
mero-agent-provision provision --gate http://<agent>:8090 --policy agent-attestation-policy.debug.json \
  --key owner.key --secrets secrets.json                    # claims it if unclaimed
```

`attest` and `provision` verify the quote (DCAP, nonce, key binding, agent policy,
not a debug TD) before anything is sent. `attest` prints the signing key an
account owner authorizes as the agent's device, and the owner key that claimed
it; authorize the signing key only when that owner is your own key.

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
