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
3. The provisioner encrypts the secrets to that key, for its agent id, and posts
   them. The first provisioner for an agent id claims it: its key is kept on the
   encrypted disk, bound into every later quote for that agent, and is the only key
   that can provision or release it.
4. The agent stores them on its encrypted disk. Nobody else, including the
   transport, sees them in plaintext.

The attestation-verifier gains an agent page, so a third party can run the
same check.

## Several agents on one TD

A TD per customer wastes most of it: mero-bot calls its model over the network, so
an agent is a Node process that mostly waits. One agent TD therefore hosts several
owners' agents, one per **slot** (mero-tee#467). The image bakes the number of slots
(`mero_agent_slots`, 8 by default) and a memory limit per agent; mdma picks the VM
size to match.

- **Per-agent claim.** An agent is named by an agent id that whoever places it
  (mdma) chooses. The first sealed bundle for an id claims a free slot for that id
  and its sender's key. Quotes are per agent: `report_data` binds the agent id, its
  signing key and its owner, so each owner verifies their own agent, not just the
  TD. The HPKE `info` binds the agent id, so a bundle for one agent never opens for
  another.
- **Per-agent keys and files.** Slot `n` has its own Ed25519 signing key, made at
  claim time, and its own directory, `agents/<n>/`. Its keys and secrets are
  readable by the gate and the group `mero-agent-<n>` only, and its state is
  writable by the user `mero-agent-<n>` only. Users are baked into the image,
  because the root filesystem is read-only.
- **Per-agent processes.** Slot `n`'s agent runs as `mero-agent@<n>.service`, as
  user `mero-agent-<n>`. It writes only its own state, sees no other process
  (`ProtectProc=invisible`), has no capabilities, and has a memory limit.
- **Release.** The owner seals `{"release": true}` for its agent. The gate stops the
  slot's unit, erases its claim, keys, secrets and state, and starts it again,
  empty, for the next owner. A slot is claimed exactly while its `id` file exists:
  it is written last on a claim and removed first on a release. Whatever an
  interrupted claim or release leaves is erased before the slot is used again.
- **What the operator learns.** `/health` gives counts only. Which agent ids a TD
  holds, and whose they are, is answered one agent id at a time, as a quote.

Sharing a TD shares its kernel: an agent that escapes its sandbox reaches the other
agents on that TD, their secrets included. An owner who needs more isolation gets a
TD of their own, with one slot. Anyone who can reach a gate can take free slots under
agent ids nobody was given. That costs capacity, never another owner's agent: each
owner's quote names the key that claimed their agent.

## The agent: mero-bot on NEAR AI Cloud

The first real agent is [mero-bot](https://github.com/calimero-network/mero-bot), run headless. It has no model inside the TD. Every model call goes to NEAR AI Cloud's private inference, and mero-bot checks NEAR's attestation itself before it sends anything:

- Intel TDX quotes for the gateway and each model replica;
- NVIDIA GPU evidence;
- the TLS key every request goes over;
- a signature on every answer.

The GPU TD of our own that this design once planned is parked.

**What the image adds** (`mero_bot_bundle`, `scripts/agent/mero-bot-agent.sh`)

- Node at `/opt/node` and mero-bot's release bundle at `/opt/mero-bot`, both checked against their sha256 in `build-inputs.lock.json`. The bundle holds mero-bot's production `node_modules`, mero-mcp included, so nothing is fetched at run time.
- Both are in the content hash.
- The agent binary is the launcher, one per slot. It waits for its slot's owner's secrets, then runs `mero-bot --headless --fixed-code --attested-only` as that slot's user.
  - Its working directory and `HOME` are on the encrypted disk.
  - Its environment holds only the allowlisted secrets.
  - Provisioning again restarts it.
  - `--attested-only` refuses a config in which any agent a turn can reach (the default, each route, and their hand-offs and fallbacks) does not check its model server's attestation. The image therefore never sends a prompt to an unattested model, whatever the owner provisions.

**Secrets the owner provisions** (`mero-agent-provision`)

| Name | |
| --- | --- |
| `MERO_AGENTS_JSON` | mero-bot's `agents.json`: NEAR profiles only (`"attest": "near"`), and the model to use |
| `CALIMERO_NODE_URL` | the owner's node |
| `CALIMERO_AUTH_TOKEN` + `CALIMERO_REFRESH_TOKEN`, or `CALIMERO_USERNAME` + `CALIMERO_PASSWORD` | the node login |
| `NEAR_AI_API_KEY` | optional: the key the profile's `apiKeyEnv` names, when the owner pays NEAR itself. Otherwise the operator's is used (below) |
| `HYPERFEED_CONTEXT` | optional: pins the feed |

**The secret the operator provisions.** mdma pays for each agent's model calls,
so it gives the agent a NEAR AI key of its own: one from its pool, sealed
straight to the gate after the owner claims the agent, so the key never passes
through the owner's browser. The gate's `/operator` takes it only from the key
the VM's `operator-key` metadata names, only for a claimed agent, only under
the names in `OPERATOR_SECRETS` (`NEAR_AI_API_KEY`), and only into the slot's
`operator/` directory, apart from the owner's `secrets/`. The operator cannot
claim or release an agent or touch the owner's secrets, and a release erases
what it wrote. What it can do is choose which NEAR key the agent pays with; a
NEAR key reaches NEAR's attested gateway like any other and reads nothing the
agent sends. mdma checks the gate's quote itself before sealing, so a fake gate
cannot collect a key.

**What this step does not do yet**

- The agent acts as its owner's node login. A login limited to the contexts the owner picks is what bounds it. Its own account, and warrants through relays (below), come later.
- The image restricts no egress. mero-bot reaches the owner's node, NEAR's gateway, Intel's PCS and NVIDIA's attestation service.
- Model choice is the owner's, through `MERO_AGENTS_JSON`, so it is not measured. What is measured is that only attested providers can be used.

**Turning it on.** A mero-bot release tag publishes `mero-bot-<version>-linux-x64.tar.gz` and its sha256. To bake it:

1. Set `meroBotVersion` in `versions.json`.
2. Run `scripts/release/pin-build-inputs.sh`, with `gh` logged in, since mero-bot is a private repo.
3. Add the `MERO_BOT_RELEASE_TOKEN` secret to this repository: a token with read access to calimero-network/mero-bot's releases.

mero-bot 0.1.1 is pinned. `Release mero-kms` then builds the release's agent image with mero-bot, and `agent-tdx-image-probe.yaml` does the same from a branch with `agent: mero-bot`. Without `meroBotVersion`, the image stays the stub. A pin without the secret fails the release's agent build, which leaves its KMS images node-only.

## Acting in Calimero: warrants through relays

The agent writes to Calimero exactly as any keyholder without an account on a
node does, and this needs no change to Core, merod, traefik or mdma. Relay
nodes already accept a warrant signed by the author's device key, committing to
the context, method and arguments (`fleet_delegated_access`; the `/intents`
routes in `traefik-routing.yml.j2`; `/sealed/v2` for sealed transport).

- The agent's signing key is generated in the TD and never leaves it.
- That key is the root of **the agent's own account**. The agent does not act
  as its owner: it is a member of the contexts its owner invites it to, and
  what it does there carries its own name. Its role caps what it can do, and
  removing it is removing a member. Because the quote binds the key (`/attest`,
  with the signing key in `report_data`), the owner's console derives the
  agent's account id from a verified quote, so nobody relaying it can swap in
  another account to be invited instead. The owner trusts a measured build, not
  an operator.
- The owner invites that account like anyone else, and seals each invitation
  to the agent as an owner secret (`MERO_INVITATION.<name>`); mero-bot joins
  each once. To work the owner's Hyperfeed it must also be added there as an
  agent (Settings → Agents → Cloud agents). It drafts what should come from the
  owner, which the owner's own client sends when approved.
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
new agent has a new signing key and so a new account, which the owner invites
again; an old agent's account is removed from the contexts it was in.

## Prerequisites

1. **Role-aware KMS policy** (above). No KMS lists an agent without it.
2. **A way to start agent VMs.** mdma deploys nodes and KMS clusters but not
   agents. A first deployment can use `gcloud` from a release script with the
   image name and `kms-url` metadata; mdma support follows if agents run as a
   fleet.
3. **An account for an attested key.** The owner's client derives the
   agent's account id from a verified quote and invites it. No Core change:
   a keyholder's join by invitation and its writes through a relay already
   exist.

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
| Sandbox escape on a shared TD | Exposes the other agents on that TD: their secrets, keys and state. | One user, one unit and one directory per agent; no capabilities. A dedicated TD for owners who need it. |
| Free slots taken by strangers | A TD fills up with agents nobody placed. | Capacity only: no owner's agent is at risk. mdma places new agents elsewhere. |
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
| 4b | mero-tee, mero-bot | mero-bot as the agent: headless, NEAR AI Cloud attested, pinned bundle and launcher (see "The agent: mero-bot on NEAR AI Cloud"). | In progress: needs a mero-bot release pinned in `versions.json` |
| 5a | mero-tee | Several owners' agents on one TD: per-agent claim, quote, signing key and release; one user and unit per slot (see "Several agents on one TD"). | Done |
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
  the owner is given another agent. No key that can provision an agent exists in CI.
- **Slots, baked.** The number of agents a TD hosts, and their users, are baked
  into the image and measured. Users cannot be added to a read-only root at run
  time, and a fixed number keeps memory limits honest.
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

- ~~A model inside the TD for the first agent, or is a hosted API acceptable?~~
  A hosted API whose TEE mero-bot attests: NEAR AI Cloud.
- ~~Where does the agent source live, and is it published?~~
  calimero-network/mero-bot, private for now; the image pins its release bundle
  by sha256 and publishes the measurements.
