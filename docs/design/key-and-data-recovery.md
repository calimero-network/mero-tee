# Design: recovering from lost TEE keys

Status: proposal. Nothing here is implemented. It builds on the frozen KMS
([gcp-tdx-kms.md](gcp-tdx-kms.md)) and keeps its main decision: nobody,
Calimero included, holds a copy of a release's root.

## Goal

A mistake by us must not lose customer data. A mistake here means a deleted
GCP project, a lapsed billing account, a bad Terraform apply, an IAM change, or
a release retired too early. The rule today is "nobody can read it". This
design keeps that rule wherever it can. Where a customer chooses to give it up,
the customer makes that choice, per namespace, knowing the cost.

## What a lost key costs today

### The KMS root

Each release has one 5-replica cluster. The root exists only in the replicas'
memory. If every replica is lost, so is the root (`kms_cluster.py` marks the
deployment failed and recreates nothing). Nodes that are still running keep
their storage key in memory. A node that restarts cannot start:
`merod run` fetches its storage key from the KMS on every boot and refuses to
start without it (`core/crates/merod/src/cli/run.rs`).

For ordinary context state, this costs nodes, not data. TEE nodes are replicas
(`ReadOnlyTee`, `RelayTee`), and members' devices hold the same state. Recovery
is the upgrade rollover, triggered early ([runbooks](../src/content/docs/operate/runbooks.mdx#recover-a-lost-cluster)).

### Where data is actually lost

| # | Data | Why it is lost |
| --- | --- | --- |
| 1 | **TEE-only secrets** (`TeeSecret<T>`, `Sealed::to_tee`) | The ciphertext replicates to every member, but only the namespace TEE vault key opens it. Only TEE authorities hold that key. Each copy reaches its TEE sealed to that TEE's identity key, which sits on a disk encrypted under the KMS root. When the KMS is gone *and* every TEE authority of the namespace has restarted, nobody can open those secrets again. `core/crates/context/src/tee_vault.rs`: "A key reaches a new TEE only while some TEE that holds it is up." |
| 2 | **Namespaces whose only durable copy is on TEE nodes** | A Calimero Cloud account holder who runs no node writes through a fleet relay. Their browser may hold little or no state, so if the fleet nodes go, the data goes with them. |
| 3 | **Anything still on release N when N is retired** | Retiring N deletes its cluster on purpose. If no release N+1 TEE has received the vault key by then, (1) applies to every namespace on N. |

### Why "every TEE restarted" is likely, not exotic

- Fleet TEE VMs run with `on_host_maintenance=TERMINATE`
  (`mdma/dispatcher/app/gcp/instances.py`) because TDX has no live migration.
  A maintenance wave restarts them. Unlike KMS replicas, they get no successor
  before it lands.
- Our own mistakes are correlated. One deleted project, billing account or
  Terraform workspace can take out the KMS cluster and the fleet together.
- Release rollover deletes the old cluster as part of normal operation.

So the dangerous state is **KMS root lost, TEE nodes still running, and
nothing stopping them from restarting**. Right now nothing detects that state.

## Principles

1. **Make losing the root cheap, don't back it up.** A root backup protects
   only node disks, and the data on them already lives elsewhere. The
   exception is the vault key, which is handled in its own section below.
2. **Recover data at the data layer.** Back up ciphertext that only existing
   readers can open. This adds no new reader.
3. **Hand keys over make-before-break.** No key holder goes away until a
   successor holds the key. This applies to KMS replicas (already done),
   TEE nodes and releases.
4. **Weakening "nobody" is opt-in, per namespace, and visible.** It is never
   a fleet-wide default.

## Design

### 1. Make deletion hard (no change to the trust model)

The likeliest failure is an operator mistake, not a TEE failure.

- **A dedicated folder for KMS and fleet projects**, with:
  - resource liens (`gcloud resource-manager liens create`) on each project;
  - an org policy, and IAM deny policies, that block
    `compute.instances.delete` and `resourcemanager.projects.delete` for
    everyone except the MDMA dispatcher's service account, and block that
    account from deleting a cluster that still has nodes (see 3);
  - a billing account used only for this folder, prepaid, with budget and
    "billing disabled" alerts sent to more than one person.
- **KMS replicas split across two projects** in that folder, so that one
  project-level mistake leaves a quorum. The join rule ("same as me") does not
  depend on the project.
- **Deletion protection** on every KMS VM and fleet TEE VM. The dispatcher
  turns it off only as part of its own delete flow.
- **Alerts** on KMS ready replicas (below 4: warn, below 3: page), on fleet
  TEE authorities per namespace (see 4), and on any IAM or org-policy change
  in the folder.

### 2. Emergency rollover while nodes are still running

When a cluster is lost, the running nodes still hold everything in memory. The
job is to move the keys to a new release root before any of those nodes
restarts.

Add a `kms_degraded` state to `KMSDeployment` in MDMA:

| Trigger | Action |
| --- | --- |
| Ready replicas ≤ 2 (configurable) | Enter `degraded`. Page. Start a **standby cluster** from the same release image: a fresh bootstrap, so a new root and a new URL. Keep replacing replicas in the old cluster as usual. |
| `degraded`, or old cluster `failed` | **Freeze TEE restarts** for nodes on this release: no rolling restarts, no image updates. For each TEE node with upcoming maintenance, start a successor on the standby cluster *before* the maintenance lands, as `kms_cluster.py` already does for replicas. |
| Standby cluster `running` | Start new TEE nodes against it. They join their namespaces, sync, receive the vault key from the old nodes still running (the existing `TeeVaultKeyDelivered` flow), and confirm. |
| Every namespace on the old nodes has a vault-key holder on the standby cluster (see 3) | Drain and delete the old nodes, the same way as a rollover. If the old cluster recovered, delete the standby cluster instead. |

This turns "lost every replica" from potential data loss into a rollover,
provided it starts before the TEE nodes restart. The freeze is what makes that
window long enough.

Starting a standby cluster in the same release is safe. Anyone can already
start a genuine cluster with another root (gcp-tdx-kms.md, "Risks"), and an
unused root reads nothing.

### 3. Make-before-break for TEE nodes and releases

Today a node can leave, and a release can be retired, without checking that
the vault key lives on somewhere. Add one check, used in three places:

> **`vault_key_safe(namespace, leaving)`**: after `leaving` is gone, at least
> `MIN_VAULT_HOLDERS` other current TEE authorities of the namespace hold a
> live vault key. "Live" means `tee_vault_keys` minus `retired_tee_vault_keys`.

- **core** exposes it as an admin API read (per namespace and per TEE), built
  on `calimero_governance_store::tee_vault`.
- **fleet sidecar:** before `meroctl namespace leave`, refuse if the leave
  would break `vault_key_safe`. Treat it like the existing "too many missing"
  guard: hold the leave and report it.
- **MDMA:** refuse to delete a TEE node, or retire a release's KMS cluster,
  while any namespace on it fails `vault_key_safe` for nodes outside that set.
  Rollover becomes:
  1. start release N+1 nodes;
  2. wait for N+1 TEEs to become authorities and receive the vault key;
  3. only then drain N.

### 4. Redundant vault-key holders

`MIN_VAULT_HOLDERS` starts at 3: three TEE authorities per namespace that has
TEE authorship turned on, placed by MDMA in at least 2 regions and on different
hosts. Placement already exists for HA groups, so this makes it a constraint
there, alerted on in 1.

### 5. Encrypted context backups (mdma#365)

These cover case 2 and "every copy lost". They add no new reader.

- **What:** each namespace's signed governance log and context deltas, as they
  are on the wire: encrypted under group keys, signed by their authors.
  Periodic snapshots make restores fast.
- **Where:** a bucket in a separate project, ideally in another cloud, with
  object versioning and a retention lock (Bucket Lock) that prevents deletes
  for N days. Writers get append-only credentials.
- **Who can read:** whoever already holds the group keys: members and admins.
  The backup holds no keys. Calimero can read nothing it cannot already read.
- **Restore:** a new node, or a member's device, imports the log and replays
  it through the normal apply path. Signatures and the DAG make a tampered
  backup fail to apply instead of silently corrupting state.
- **`TeeSecret` cells** are backed up as ciphertext too. They are useful again
  only if the vault key survives (sections 3, 4 and 6).

**Recovery kit for Cloud users.** A backup is useless to a user who has lost
every key. When an account is created or joins a namespace, offer a
recovery-kit export: the account root key and the group keys it holds,
encrypted under a passphrase, as a file. The agent console already does this
for owner keys. Without it, the backup protects only users who run a node.

### 6. Opt-in vault-key escrow per namespace

Some apps can lose TEE secrets: a card game redeals. Others cannot, such as an
app that keeps a signing key or credentials in a `TeeSecret`. Add a namespace
policy op, `TeeVaultEscrowSet`, signed by an admin and logged in governance so
every member can see it:

| Mode | Who else can open the vault key | What it costs |
| --- | --- | --- |
| `none` (default) | nobody | Lost if every holder is lost. Today's behavior. |
| `cold-tee` | A **standby TEE authority**: a TEE node of a different kind, either another cloud with TDX (Azure) or an AMD SEV-SNP vault image. It runs only to hold the key and almost never restarts. | Adds a second hardware or vendor root of trust: if either vendor is broken, the vault key leaks. No person can read it. |
| `admin-threshold(k, n)` | k of the n named admins together. The vault key is Shamir-split, and each share is sealed to one admin's key and logged. | The customer can read their own TEE secrets. For a game, that means the house can see the deck. That is acceptable for some apps and fatal for others, which is why it is per namespace. |

Both modes use existing machinery. `cold-tee` is one more recipient of
`TeeVaultKeyDelivered`. `admin-threshold` is a new delivery shape that only a
TEE can log (the same rule as today: a key an admin handed the TEEs would let
that admin read every secret). The SDK should expose the namespace's mode, so
an app can refuse to run under a mode it does not accept.

Rotation keeps working. When a holder retires, a new vault key is created and
escrowed under the same mode. Old escrowed keys keep opening old ciphertext,
which is the point.

### 7. KMS root escrow (deferred, not recommended now)

Sections 1-5 make losing the root a rollover. Escrow the root itself only if
the business needs the root to survive without one. If it ever does, use the
`cold-tee` shape: a frozen escrow image whose measurements are baked into the
KMS image, and which releases the root only to a TD that measures exactly like
the KMS. Keep rejecting the k-of-n custodian split for the root
(gcp-tdx-kms.md, "Decisions"): it turns "nobody" into "k of our staff",
fleet-wide.

## Trust model changes

| Section | Change |
| --- | --- |
| 1-5 | None. 5 stores ciphertext that only current readers can open. |
| 6 `cold-tee` | Adds a second TEE vendor or cloud as a reader of that namespace's vault key, opt-in. |
| 6 `admin-threshold` | Lets k admins of that namespace read its TEE secrets, opt-in and visible in governance. |
| 7 | Not proposed. |

## Work

| Phase | Where | Work |
| --- | --- | --- |
| 0 | ops | Folder, liens, deny policies, billing isolation, alerts (section 1). Staging drill: kill every KMS VM, then restart every TEE node, and measure what survives. Run it before and after phases 1-2. |
| 1 | mdma | `degraded` state, standby cluster, freeze on TEE restarts, maintenance successors for TEE nodes (section 2). |
| 1 | core | `vault_key_safe` admin-API read. |
| 2 | mero-tee, mdma | Sidecar leave guard; MDMA delete and retire guards; make-before-break rollover (section 3). Placement constraint `MIN_VAULT_HOLDERS` (section 4). |
| 3 | mdma, core | Encrypted backups to locked storage, plus restore via replay (section 5, mdma#365). |
| 3 | mero-js, clients | Recovery-kit export and import. |
| 4 | core, mero-tee | `TeeVaultEscrowSet`; `cold-tee` holder image; `admin-threshold` delivery; SDK exposes the mode (section 6). |

## Open questions

- Is 3 the right `MIN_VAULT_HOLDERS`, and should it scale with how much a
  namespace pays for?
- For `cold-tee`, which second platform: Azure TDX (same vendor, different
  cloud and firmware) or AMD SEV-SNP (different vendor)? The second protects
  against more failures but needs its own attestation path in core.
- How long a retention lock should backups have, and does a user's deletion
  request (GDPR) override it? Crypto-shredding works here: deleting the
  group keys makes the backup unreadable.
- Should a namespace with `TeeSecret` state and escrow `none` show its users a
  warning that the state can be lost?
