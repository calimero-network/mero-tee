# Design: private agents on GCP TDX

Status: prototype. Phases 1-4 are implemented in this repository. Phases 5-8,
always-on agents scoped to the contexts their owners pick, many to an agent TD,
are planned below under "Always-on agents". See [How it works](../src/content/docs/flows/private-agents.mdx)
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
- The agent is its own account, rooted at that key, not a device of its
  owner's account. The owner admits that account to the groups it may use,
  after checking that the agent's quote binds the key (`/attest`, with the
  signing key in `report_data`). The owner trusts a measured build, not an
  operator. See "Always-on agents" for why.
- The agent seals its intents to a relay over `/sealed/v2`, so the relay
  operator does not see the arguments in transit.

## Always-on agents

The product is an agent that keeps working while its owner is offline, and acts
only in the contexts its owner scopes it to. Never as the owner, never
elsewhere.

**Scope is membership.** The agent is its own account. Its owner puts the
contexts it may use in a `Restricted` subgroup and admits the agent's account
there, and nowhere else:

- Role `Member` where it writes and `ReadOnly` where it only reads.
- Capabilities stripped to none: no `CAN_INVITE_MEMBERS`, `MANAGE_*`,
  `CAN_JOIN_OPEN_SUBGROUPS` or `CAN_AUTHOR_ON_BEHALF`.
- Removing it is `members/remove` on that subgroup. The owner's own devices are
  untouched, which they would not be if the agent were one of them, and a device
  of the owner would act with the owner's full reach, not a scoped one.
- Relays already enforce the author's role: a warrant from an author that is
  `ReadOnly` in the context is refused (Core,
  `protocol/delegated-authorship.mdx`).

**The network knows it is an agent, and whose.** The agent gets its own key and
its own agent account, rooted at the key the gate generates in the TD; it is
never one of its owner's devices. Every member then sees, for that account,
that it is an agent and which account answers for it:

- The marker is signed by the owner, not by the agent: "account X is an agent
  of account O". Peers accept it only from O, and only while O is a member of
  the group the agent is in, so the agent can neither claim an owner nor drop
  its marker.
- Member metadata (`GroupOp::MemberMetadataSet`) is not enough on its own: a
  member may set its own metadata, so an agent could rewrite or remove a flag
  kept there. The marker needs a governance op of its own (or a field on the
  admission op) that only the owner signs and peers cannot see the agent undo.
- Apps and clients show the marker beside the agent's writes ("agent of
  Alice"); a warrant already names the author's account, so nothing per write
  changes.

**Nobody talks to the agent directly.** The agent runtime is mero-bot, and its
owner reaches it through the owner's Hyperfeed: at claim, the owner and the
agent share a feed, and that is the agent's home. Other people reach it only by
writing in a context it is a member of, and it answers there. It wakes on its
contexts' events, reads through its relay and replies with a warrant. So:

- The agent TD serves no API for conversation. Its only inbound endpoints are
  the gate's `/health`, `/attest` and `/provision`, for its owner's claim, and
  nothing else is reachable from outside the TD.
- Who may talk to it is who may write in its contexts: membership already
  decides it, and the conversation is kept, synced and access-controlled like
  any other state.
- Instructions come from the owner's feed only. Anyone who can write in a
  scoped context can put text in front of the agent, so it treats everything
  it reads elsewhere as data, and its scope bounds what a successful injection
  can reach.
- mero-bot today runs beside its owner's own node. In the agent TD it has no
  node: it reaches Calimero as a tenant of its relay (the paths below, sealed
  with mero-js's sealed transport) and the model through mdma's sealed
  gateway, and the gate signs for it.

**Agents are tenants on the shared relay fleet, like cloud users.** mdma already
serves many accounts from one relay merod: each account keeps its keys outside
the node, and the relay acts only on what that account signs or may see. An
agent is one more such account, and Core serves everything it needs today:

| Need | Core path | Checked against |
| --- | --- | --- |
| Write | Warrant to `POST /contexts/{id}/intents` | The author's role in the context; the relay must be `RelayTee` |
| Read | `POST /admin-api/contexts/{id}/query`, read-only methods only | The account's membership, re-checked per call under the execution lock |
| Wake on new items | Event subscription from an account session | The account's membership; the grant is re-derived on a membership change |
| Find its contexts | Caller-scoped `GET /admin-api/contexts`, `/namespaces` | Only the account's own groups |

So the agent holds no group keys, and an agent compromise exposes only that
agent's own account and secrets. Reads and event streams are sealed on a relay
with `forward_auth` (Core, `protocol/client-paths.mdx`).

**Many agents per agent TD.** The agent side is multi-tenant too, so an agent
costs a process, not a VM:

- The gate holds every agent's signing key on the encrypted disk and signs
  warrants and query sessions only for the agent that asks. It never hands a
  key to an agent process.
- Each agent has its own owner claim, secrets directory and Unix user. Agent
  processes are sandboxed (systemd per-agent units, no access to the gate's
  key store or another agent's directory).
- `/attest` names the agent: its signing key and owner key in `report_data`,
  so an owner checks the quote for their agent, not just for the VM.
- Tenants share a TD, so a bug that escapes an agent's sandbox reaches the
  other agents on it. That is the price of packing, as it is for tenants on a
  shared relay; an owner who wants isolation gets a dedicated agent VM.

**The model.** The agent's model runs in a separate confidential GPU TD (one
H100 for the pilot). The gateway is part of mdma, and the traffic through it is
sealed end to end, as delegated execution's is through a relay:

- The GPU TD runs the sealed transport Core's server uses (`/sealed/v2`: a
  Noise NK session to a transport key bound into the TD's quote). The agent
  verifies that quote and seals every model request to the GPU TD.
- mdma's gateway sees the outer request only: which agent account, signed by
  its key, and the size. It checks the agent's plan and quota, picks a GPU TD,
  and forwards the sealed body. It cannot read a prompt or a completion.
- Token counts come from inside the GPU TD: it returns a usage record signed
  by its attested key with each response, outside the sealed body, and mdma
  bills from those. mdma meters requests on its own; tokens it can only take
  from the TD.
- What mdma learns is metadata: which agent called, when, and how large. Keep
  per-request records only as long as quota needs them, and daily totals for
  billing.

The agent image stays CPU-only.

What one GPU TD carries is measured, not assumed: the `GPU model probe`
workflow (`scripts/release/model/`) pins a model to a Hub commit and the sha256
of every file, serves it with vLLM on a confidential a3-highgpu-1g VM, and
reports time to first token, decode speed per user and turns per day under a
Hyperfeed-shaped load (a 10k-token turn sharing a 4k-token brief, 500 tokens
out). It publishes nothing; the image build that bakes the weights comes after.

**Who does what.**

- mdma deploys and stops agent VMs, holds the plan and the quota, runs the
  model gateway (sealed traffic it cannot read), and bills usage. It never holds an agent's keys and never
  signs a membership change.
- The owner's client (console in the browser, or CLI) claims the agent, checks
  its quote, and signs the admission into the scoped subgroup.
- Stopping the VM and refusing the agent at the gateway is the immediate stop.
  Removing the agent from its subgroup is the cryptographic one.

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

**A new TEE member type for agents.** An agent admitted as a TEE member, with a
member type whose admission policy names agent measurements, would let peers
check that a member is an attested agent build. It is not needed for reading:
an agent reads as a tenant through a relay. It waits for a reason to require
attestation of the member itself.

**One merod per agent.** It gives each agent the group keys of exactly its
groups and needs no relay, but costs a node per agent, while tenancy on the
relay fleet costs nothing per agent and keeps keys out of the agent.

## Work

| Phase | Where | Work | Status |
| --- | --- | --- | --- |
| 1 | mero-kms, mero-tee | Role-tagged policy entries, all five registers matched within one entry; per-role key prefix; optional agent policy in the KMS image. | Done |
| 2 | mero-tee | `agent` image role, `playbook-agent.yml`, `mero-agent` role with `agent-init`. | Done, every profile |
| 3 | mero-tee | `mero-agent-gate`: `/attest` and sealed secret provisioning; verifier page for agent quotes. | Done, with `mero-agent-provision` |
| 4 | mero-tee | Release: build and measure the agent image, add it to the KMS policy, publish its measurements; post-release e2e. | Done, best effort in `release-kms.yaml` with the stub agent as the reference agent; `post-release-agent-e2e.yaml` |
| 5 | mero-tee, agent, client | Multi-tenant agent TD: the gate holds one signing key, claim and secrets directory per agent and signs only for that agent; sandboxed agent processes; per-agent `/attest`. Agent runtime reading with `/query`, waking on events, writing with warrants through its assigned relay. Owner-side check of the agent's quote before admitting its account to a scoped `Restricted` subgroup. | Planned |
| 6 | mdma | `Agent` record (owner, agent TD, relay, status, plan); place agents on agent TDs as it places accounts on relays; deploy, roll over and retire agent TDs; console page; `agents` and `turns_per_day` on the plan; daily usage totals billed as metered usage. | Planned |
| 7 | mero-tee, mdma | Confidential GPU image: model server behind the sealed transport, signed usage records, weights baked and pinned by sha256. mdma gateway: agent-signed requests, plan and quota, routing to a GPU TD, billing from signed usage. | Planned |
| 8 | Core | Owner-signed agent marker ("X is an agent of O") that the agent cannot remove; invitations that carry a role and capabilities, so an agent joins scoped from the start (today an invitation always grants `Member`). | Planned |

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

Decided:

- **The first agent's model runs in Calimero's own confidential GPU TD**, not a
  hosted API.
- **An agent acts only in the contexts its owner scopes it to**, as its own
  account, never on its owner's behalf.

- **Agents of different owners share an agent TD**, as tenants share a relay;
  a dedicated agent VM is an option for an owner who wants isolation.

Still open:

- Where does the agent source live, and is it published?
