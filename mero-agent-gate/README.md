# mero-agent-gate

Attestation and sealed secret provisioning for the private agent TDX image
([design](../docs/design/private-agents.md), [how it works](../docs/src/content/docs/flows/private-agents.mdx)).

The gate runs beside the agents in the agent image. One agent TD hosts several
owners' agents, one per **slot** (mero-tee#467). The gate proves which image
runs, holds each agent's signing key, and takes each agent's secrets only sealed
to this TD and only from that agent's owner. An agent can then be any program:
it reads its secrets from files on the encrypted disk and signs with the key the
gate attested for it.

## Agents and slots

An agent is named by an **agent id**, `[a-z0-9][a-z0-9-]{0,62}`, which whoever
places it (mdma) chooses. The image bakes a fixed number of slots (`GATE_SLOTS`).
Slot `n` has its own Unix user and group, `mero-agent-<n>`, its own unit,
`mero-agent@<n>.service`, and its own directory on the encrypted disk:

| Path | Owner, mode | What |
|------|-------------|------|
| `agents/` | root, 0711 | Every slot's user passes through to its own slot and lists no other |
| `agents/<n>/id` | root:`mero-agent-<n>`, 0640 | The agent id holding the slot. Written last on a claim and removed first on a release, so a slot is claimed exactly when it exists |
| `agents/<n>/keys/owner.x25519` | root:`mero-agent-<n>`, 0640 | The owner's X25519 public key |
| `agents/<n>/keys/signing.ed25519` | root:`mero-agent-<n>`, 0640 | The agent's Ed25519 seed |
| `agents/<n>/secrets/<NAME>` | root:`mero-agent-<n>`, 0640 | What the owner provisioned |
| `agents/<n>/operator/<NAME>` | root:`mero-agent-<n>`, 0640 | What the operator provisioned: `NEAR_AI_API_KEY` only |
| `agents/<n>/state/` | `mero-agent-<n>`, 0700 | The agent's own files |

No agent reads another's keys, secrets or state. Each unit runs as its slot's
user, may write only its own `state/`, and sees no other process
(`ProtectProc=invisible`). A slot without an `id` is free; whatever an
interrupted claim or release left in it is erased before anyone else gets it.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | `{"status":"ok","slots","claimed","free","provisioned"}`: counts only. Which agents a TD hosts, and whose they are, is asked one agent id at a time |
| `POST` | `/attest` | `{"nonceB64","agentId"?}` → a quote whose report data is `nonce ‖ SHA-256("mero-agent-gate/attest/v3" ‖ provisioning_pub ‖ len(agent_id) ‖ agent_id ‖ signing_pub ‖ owner_pub)`, and the keys. While the agent is unclaimed, `signing_pub` and `owner_pub` are 32 zero bytes and `signingPublicKeyB64` and `ownerPublicKeyB64` are absent. Without `agentId`, the quote is for the TD alone (an empty id): what the release pipeline measures |
| `POST` | `/provision` | An HPKE message for `agentId`, sealed to the provisioning key, with its sender's key. The first one for an unknown agent id claims a free slot for it and its sender. Writes each secret to the slot's `secrets/<NAME>` and answers `{"written","claimed"}`. `403` if another key owns the agent or the sender did not seal it for this agent, `409` if it was sealed to a key from an earlier start, `503` `no_free_slot` if every slot is taken |
| `POST` | `/operator` | The same shape, from the **operator**: the key the VM's `operator-key` metadata names (agent-init writes it to `GATE_OPERATOR_KEY_FILE`), sealed under its own domain. Writes only the names in `OPERATOR_SECRETS` (`NEAR_AI_API_KEY`) to the slot's `operator/`, and only for a claimed agent. `403` `not_the_operator` from any other key or with no operator key, `404` for an agent nobody claimed, `400` for any other name |
| `POST` | `/release` | The same shape, sealing `{"release": true}`, from the agent's owner: the gate stops the slot's unit, erases its `id`, keys, secrets and state, and starts the unit again, empty. Answers `{"released"}`; `404` for an unknown agent id |

## Keys

- **Provisioning key**: X25519, generated in memory at every start, never written. Shared by every agent on the TD.
- **Signing key**: Ed25519, one per agent, generated in the TD when the agent is
  claimed, at `agents/<n>/keys/signing.ed25519` on the encrypted disk. The gate
  runs as root, which configfs-tsm quotes need; the agent reads its own key
  through its slot's group.
- **Owner key**: the X25519 public key that claimed the agent, at
  `agents/<n>/keys/owner.x25519`. Never replaced while the agent exists: a new
  owner means a release, which erases the agent's signing key too.

## Provisioning protocol

RFC 9180 HPKE: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305.
`info = "mero-agent-gate/provision/v2" ‖ provisioning_pub ‖ len(agent_id) ‖
agent_id`, empty AAD, so a message opens only on this start of this TD and only
for the agent it names. Plaintext `{"secrets": {"NAME": "value"}}`, at most 64
secrets of 64 KiB, names `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`; or `{"release":
true}`. Always Auth mode, under the sender's X25519 key.

**Operator secrets.** `/operator` takes the same request, with
`info = "mero-agent-gate/operator/v1" ‖ provisioning_pub ‖ len(agent_id) ‖
agent_id`, so an owner's message never opens as the operator's or the other way
round. Its sender must be the operator key. It is how mdma, which pays for the
agent's model calls, gives the agent its NEAR AI key without that key passing
through the owner's browser. The operator can neither claim, release nor write
the owner's `secrets/`; the launcher uses the operator's `NEAR_AI_API_KEY` only
when the owner provisioned none.

**Owner claim.** Nobody is baked in as allowed to provision, so neither who
builds the image nor who runs the VM chooses who sets an agent's secrets. The
first bundle for an agent id that opens under its sender's key and is valid
claims a free slot for that id and key: the gate stores them on the encrypted
disk before writing any secret, and binds them into every later quote for that
agent. From then on only that key can provision or release it.
`mero-agent-provision` refuses an agent whose quote binds another owner before
sending anything, since that owner could read what it is given. After
provisioning, it attests again and checks the fresh quote binds its own key.

Whoever reaches a fresh agent id first can claim it. That race is visible, not
silent: the claimant's key is in every quote for that agent, so the real owner
sees "not yours", sends nothing, does not authorize its signing key, and is
given another agent id. Anyone who can reach the gate can also take free slots
under ids nobody was given; that costs capacity, never another owner's agent.

## `mero-agent-provision`

The provisioner's CLI, in this crate:

```bash
mero-agent-provision keygen --out owner.key                 # keep it; prints the public key
mero-agent-provision attest --gate http://<agent-td>:8090 --policy agent-attestation-policy.debug.json \
  --agent <id> --key owner.key                              # fails unless unclaimed or yours
mero-agent-provision provision --gate http://<agent-td>:8090 --policy agent-attestation-policy.debug.json \
  --agent <id> --key owner.key --secrets secrets.json       # claims a slot if unclaimed
mero-agent-provision release --gate http://<agent-td>:8090 --policy agent-attestation-policy.debug.json \
  --agent <id> --key owner.key                              # stops it and erases its slot
```

`attest`, `provision` and `release` verify the quote (DCAP, nonce, agent id, key
binding, agent policy, not a debug TD) before anything is sent. `attest` prints
the agent's signing key, and the owner key that claimed it. The signing key is
the root of the agent's own Calimero account: its account id is derived from
it, so the id you invite follows from the verified quote. Invite it only when
that owner is your own key.

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
