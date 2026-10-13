# Design: private agents on GCP TDX

Status: prototype. Phases 1-3 are implemented in this repository, and phase 4
has a measurement probe. Phase 4's release and phases 5-6 wait on the open
decisions below. See [How it works](../src/content/docs/flows/private-agents.mdx)
for the protocol as built.

Run agents next to the Calimero fleet as a third TDX image role, `agent`, so
nobody but the agent can read its secrets, signing key or state. Anyone can
still check which build runs.

## At a glance

The agent's keys are generated inside the TD. The KMS releases its disk key
only to an attested agent image. Provisioners and account owners check the
agent's quote before sending secrets or authorizing its key. Relays carry its
signed warrants into Calimero.

## Why a third image, not a sidecar

The node image could run the agent as one more systemd unit. It is the cheaper
build and the wrong boundary:

- **Coupled releases.** The agent would be in every node's measurements, so
  each agent change becomes a node release, a new KMS cluster and a fleet
  rollover.
- **A larger trusted base.** Agent dependencies (an LLM SDK, a language
  runtime, the tools it calls) would sit beside merod, traefik and mero-auth in
  the code that holds node storage keys. An agent bug would expose the node.
- **Shared fate.** Nodes and agents could not scale or fail independently.

An agent acts in Calimero as an author through relay nodes. It is not a node
and holds no group keys.

## Image and boot

The agent image is built by the same template as the node and KMS
(`mero-tee/ubuntu.pkr.hcl`) and sealed the same way.

**Image**

- `image_role = "agent"`, built from a new `playbook-agent.yml`: the KMS
  playbook's base (`cleanup`, `merod-lockdown` on `locked-read-only`,
  `verity-root`, the log and metric shippers) plus a new `mero-agent` role with
  the agent binary, `agent-init` and its units.
- Name and family `merotee-agent-<profile>-<version>` and
  `merotee-agent-<profile>`, plus the usual `-dev` family. mdma's dispatcher
  resolves node images by exact prefix, so it can never pick this one up.
- The content hash (`calimero.root_hash`, RTMR2) covers `/etc/mero-agent`,
  `/usr/local/lib/mero-agent` and the agent binary. dm-verity is what stops an
  offline edit of the disk.
- The binary is passed in like `mero_kms_binary`: an artifact the release
  workflow downloads and checks against a pinned digest. Its source may be
  private; its measurements are still published.
- Instance metadata carries addresses only (`kms-url`, the relay URL). Prompts,
  tools, model choice and limits are baked in and measured.

**Boot (`agent-init`)**

1. Extend RTMR3 with `calimero-rtmr3-v2:agent:<profile>:<root_hash>`, fatal on
   `locked-read-only`. The role string is what tells an agent quote from a node
   quote.
2. Generate an identity key inside the TD, fetch the data-disk key from the KMS
   over the existing `/challenge` → `/get-key` handshake, and open the
   encrypted data disk.
3. Start the agent once the disk is open. Its state lives there only; `/tmp`
   and `/var` are tmpfs, as on the KMS.

## Secrets reach the agent sealed to it

The image is public, so it cannot hold the agent's secrets (model API keys,
tool credentials). They are provisioned after boot, encrypted to the TD:

1. The agent serves `/attest`: a TDX quote whose `report_data` binds a fresh
   nonce to its provisioning public key, an HPKE key generated in the TD.
2. The provisioner verifies the quote against the agent release's published
   measurements.
3. The provisioner encrypts the secrets to that key and posts them. The first
   provisioner claims the agent: its key is kept on the encrypted disk, bound into
   every later quote, and is the only key that can provision again.
4. The agent stores them on its encrypted disk. Nobody else, including the
   transport, sees them in plaintext.

The attestation-verifier gains an agent page, so a third party can run the
same check.

## Acting in Calimero: warrants through relays

The agent writes to Calimero exactly as any keyholder without an account on a
node does, and this needs no change to Core, merod, traefik or mdma. Relay
nodes already accept a warrant signed by the author's device key, committing to
the context, method and arguments (`fleet_delegated_access`; the `/intents`
routes in `traefik-routing.yml.j2`; `/sealed/v2` for sealed transport).

- The agent's signing key is generated in the TD and never leaves it.
- An account owner authorizes that key as a device of the account the agent
  acts for, after checking that the agent's quote binds the key (`/attest`,
  with the signing key in `report_data`). The owner trusts a measured build,
  not an operator.
- The agent seals its intents to a relay over `/sealed/v2`, so the relay
  operator does not see the arguments in transit.

## The KMS has to tell agents from nodes

Before phase 1, mero-kms had no notion of role. Adding agent measurements to
its policy as it stood would have been unsafe, for two reasons:

- **Per-register matching.** `enforce_attestation_policy`
  (`mero-kms/src/handlers/get_key.rs`) checked MRTD and each of RTMR0–3 against
  its own allowlist. With one image listed that means "is this image"; with
  two, it accepts any mix of values from either, including combinations no
  released image produces.
- **No role in the key path.** Keys were
  `HKDF(root, "merod/storage/{profile}/{peerId}")` (`key_path_for_peer`). An
  agent and a node with the same peer ID would get the same key. The peer
  signature makes that hard to exploit, since the requester must hold the peer
  key, but separation should not rest on that alone.

**The change (phase 1, implemented)**

- The policy is a list of entries, one per role. Each entry has its own MRTD
  and RTMR0–3 allowlists. A quote passes only if all five registers match the
  lists of ONE entry, and that entry's role is the role of the request. The
  node policy is the single `node` entry, unchanged.
- The KMS infers the role from the matched entry; the requester does not state
  it. merod's `kms disk-key` client needs no change, and an agent image can
  reuse it.
- Each role gets its own key prefix. Node keys keep
  `merod/storage/{profile}/{peerId}` byte for byte. Agent keys are
  `mero-agent/storage/{profile}/{peerId}`, so an agent can never derive a node
  key, whatever peer ID it presents.
- The KMS image takes an optional agent policy file (`kms_agent_policy_file`)
  beside `kms_node_policy_file`. merod and the agent pin the KMS by its
  measurements, as nodes do now.

## Release and deployment

Start with one release train and split agents onto their own KMS cluster when
they release more often than nodes. The KMS freeze rule makes its policy part
of its image, so new agent measurements need a new KMS image, cluster and root.
The KMS change above supports both models:

| Model | What ships | Cost |
| --- | --- | --- |
| One release train (start here) | One umbrella release: node image, agent image, and a KMS whose policy lists both. One cluster per release. | An agent change rolls the node fleet, and a node change rolls the agents. |
| KMS cluster per agent release | Same mero-kms binary and image, built with the agent policy only. | Five more VMs per live agent release. |

Either way, a new release means a new root, so the previous release's agent
disk can never be reopened. The disk is a cache: anything that must outlive a
release lives in Calimero (written through warrants) or is re-provisioned. A
new agent has a new signing key, which the account owner authorizes again; old
keys are revoked when old agents are deleted.

## Prerequisites

1. **Role-aware KMS policy** (above). No KMS lists an agent without it.
2. **A way to start agent VMs.** mdma deploys nodes and KMS clusters but not
   agents. A first deployment can use `gcloud` from a release script with the
   image name and `kms-url` metadata; mdma support follows if agents run as a
   fleet.
3. **Device authorization for an attested key.** The owner's client must
   verify an agent quote before adding its key as a device. If Core's
   device-add API cannot carry that check, it lives in the client.

## Trust that remains and risks

Everything in the KMS design's trust base remains (Intel TDX and PCS, Google's
TDX firmware, the release workflow), plus:

- **What the agent sends out.** Prompts sent to a hosted model API leave the TD
  and are visible to that provider. "Private" covers what the agent holds, not
  what it chooses to send. A model inside the TD removes this, at a cost in VM
  size.
- **Closed agent code.** With private source, a verifier can confirm which
  build runs, not what it does. Trusting its behavior needs the source or an
  audit.
- **The relay.** It sees which contexts an agent writes to and when, though not
  sealed arguments, and it can refuse to relay.

| Risk | Effect | Mitigation |
| --- | --- | --- |
| Agent compromise | Exposes the agent's own secrets; an attacker acts as it within its account. No node or group keys. | Scope the agent's account to what it needs. |
| Owners do not re-authorize at a release | The agent stops working at rollover. | Start new agents and request authorization before deleting old ones. |
| Release coupling | In the one-train model, agent and node releases roll each other. | Move agents to their own KMS cluster. |

## Considered and rejected

- **Agent as a sidecar in the node image.** See "Why a third image".
- **Agent policy loaded by the KMS at runtime** (from metadata or a URL), to
  avoid a KMS release per agent release. Whoever controls that source decides
  which code gets keys: the problem the frozen KMS exists to close.
- **A separate agent-only KMS binary.** The KMS change is small, and one binary
  serves both deployment models.

**Later: agents as TEE members.** An agent that must read private context state
needs group keys, so it must be admitted as a TEE member and run its own merod.
Core admits `ReadOnlyTee` and `RelayTee` today; an agent needs a member type
whose admission policy names agent measurements, and mdma would assign agents
to namespaces as it assigns relays. That spans Core, mdma and this repo, and
should wait for an agent that needs it.

## Work

| Phase | Where | Work | Status |
| --- | --- | --- | --- |
| 1 | mero-kms, mero-tee | Role-tagged policy entries, all five registers matched within one entry; per-role key prefix; optional agent policy in the KMS image. | Done |
| 2 | mero-tee | `agent` image role, `playbook-agent.yml`, `mero-agent` role with `agent-init`. | Done, every profile |
| 3 | mero-tee | `mero-agent-gate`: `/attest` and sealed secret provisioning; verifier page for agent quotes. | Done, with `mero-agent-provision` |
| 4 | mero-tee | Release: build and measure the agent image, add it to the KMS policy, publish its measurements; post-release e2e. | Done, best effort in `release-kms.yaml` with the stub agent as the reference agent; `post-release-agent-e2e.yaml` |
| 5 | agent, client | Warrant integration through relays; owner-side device authorization with a quote check. | |
| 6 | mdma | Optional: deploy agents and run rollovers. | |

## Decisions taken while building the prototype

- **Who may provision: the owner who claims the agent.** A first prototype baked
  a list of provisioner keys into the image. That let whoever builds the image
  (Calimero) choose who sets every agent's secrets, so it was dropped. Now nothing
  is baked: the first valid HPKE Auth-mode bundle claims the agent for its
  sender's X25519 key, which the gate stores on the encrypted disk and binds into
  every quote. Only that key provisions again. A claim race is visible, not
  silent: the real owner's CLI sees another key in the quote, sends nothing, and
  the owner replaces the VM. No key that can provision an agent exists in CI.
- **The gate holds the signing key.** It generates the Ed25519 key on the
  encrypted disk and attests it beside the provisioning key, so the agent needs
  no attestation code of its own.
- **`tee-release-version` is required metadata**, as on a node: `merod kms
  disk-key` verifies the KMS against that release's signed policy, never older
  than the image.
- **`ephemeral-store=true`** keeps state in TD memory and needs no KMS. It exists
  for the measurement VM, which runs before any KMS lists the image.
- **The agent's own journal is not shipped.** Only agent-init and the gate log
  off the VM; the gate logs secret names, never values.

## Open decisions

A real agent binary, and phases 5-6, need these decisions first:

- A model inside the TD for the first agent, or is a hosted API acceptable?
- Where does the agent source live, and is it published?
