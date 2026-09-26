# Design: a frozen KMS on GCP TDX, without Phala

Status: proposal. Tracks #338; replaces the dstack/Phala KMS.

## Goal

Nobody can read a node's storage or data-disk key: not Calimero, not an
operator holding a cloud account, not a multisig, not Phala. Every upgrade
ships new nodes with new keys; nothing re-keys an existing node.

## Why not dstack

A node's key is derived from the KMS's dstack **app** key. dstack gives that
key to whatever code the app's owner approves, so the owner can always read
node keys by approving code that prints them. An on-chain allowlist makes that
public, and a multisig makes it harder, but neither makes it impossible.
Freezing the app (add one compose hash, `disableUpgrades()`, give up
ownership) is the only way to close it on dstack, and `DstackApp` is designed
to refuse that (`renounceOwnership()` reverts; dstack#1293). Phala also stays
in the trust base as the owner of dstack's root KMS and platform contract.

## Design

The KMS becomes a second locked GCP TDX image, built, measured, released and
deployed by the same pipeline as the node image (`mero-tee/playbook.yml`,
`release-node-image-gcp.yaml`). One KMS **cluster** serves one release.

### The root key lives only in the cluster's memory

- A cluster is 5 KMS VMs across 3 zones in at least 2 regions.
- The first VM (started with `kms-bootstrap=true` metadata) generates a random
  32-byte root inside the TD. It is never written to disk and never leaves a
  TD.
- Every other VM **joins**: it fetches the root from a running peer over an
  attested channel (below). A VM without `kms-bootstrap` never generates a
  root, so a network partition cannot split the cluster into two roots.
- Node keys are `HKDF(root, "merod/storage/{profile}/{peerId}")` and the disk
  key likewise, the same paths mero-kms derives through dstack today. The
  transport key for sealed release is derived from the root too, so every
  replica holds the same one.

### The freeze rule: "same as me"

A KMS VM gives the root only to a VM whose TDX quote carries **exactly its own**
MRTD and RTMR0–3. There is no allowlist, no config and no owner. The only code
that can ever hold the root is the code already holding it. The quote must
also:

- **not be a debug TD.** The `TDATTRIBUTES` debug bit leaves the measurements
  unchanged but lets the host read TD memory, so a debug TD is refused whatever
  it measures as.
- **carry a TCB status in the image's baked policy.** Measurements are compared
  exactly; the TCB status is not required to be `UpToDate`. When Intel publishes
  a new TCB level, quotes read `OutOfDate` until Google patches the hosts. A
  strict rule would refuse every replica restarted in that window, and one
  maintenance wave could drain the cluster.

### The image holds no secrets

The KMS image is public: built from open source, with published measurements,
and exportable by any project admin. So it is not encrypted, because an
encrypted image needs a boot key from somewhere, and whoever holds that key
reads it. It needs integrity instead (dm-verity, under Prerequisites). The root
is created at boot, inside the TD, and each way it could leave is closed:

| Way out | Closed by |
| --- | --- |
| Host or hypervisor reads TD memory | TDX memory encryption |
| Debug TD | Debug bit refused, in the join and in merod's KMS check |
| Disk: every write passes the host in plaintext | Nothing is written. Read-only verity root; `/tmp` and `/var` on tmpfs; no swap, no core dumps, volatile journal |
| Shell, SSH, console | The node image's locked-profile lockdown |
| Logs or the API | mero-kms never logs or returns the root; only derived, sealed keys leave, to attested nodes |
| A modified image that still attests as genuine | dm-verity |

### Join protocol

Both sides must attest. If the joiner did not verify the giver, anyone could
hand a joiner a root they chose, and then know every key it derives.

1. The joiner generates an ephemeral X25519 keypair and asks a peer for a
   nonce.
2. The joiner sends a quote with `report_data = SHA-256(nonce ‖ joiner_pub)`.
3. The giver verifies the quote (`dcap-qvl` against Intel PCS, as
   `calimero-tee-attestation` does today) and checks that its measurements
   equal the giver's own.
4. The giver HPKE-encrypts the root to `joiner_pub` and returns the ciphertext,
   the HPKE encapsulated key, and its own quote with
   `report_data = SHA-256(nonce ‖ joiner_pub ‖ enc)`.
5. The joiner verifies the giver's quote the same way (the measurements must
   equal its own) before it decrypts and accepts the root.

Peer addresses come from instance metadata. They are untrusted: a wrong
address only fails the join.

### What nodes get

The KMS image bakes in the node allowlist: the MRTD and RTMR0–3 of the node
image it is released with. The allowlist is part of the KMS image's own
measurements, so changing it produces a different KMS, which the running
cluster refuses to join. `/challenge` and `/get-key` keep today's protocol:
single-use nonce, a quote bound to the peer ID, a libp2p signature, and sealed
release.

Challenges have to work across replicas behind one URL. Two ways: sticky
routing per node, or a stateless challenge (`nonce = HMAC(root_challenge_key,
challengeId ‖ expiry)`) that any replica can check, with a per-replica replay
cache. With either, the TTL bounds the replay window. Redis goes away: it was
never trusted.

### What nodes check

merod pins the KMS by its measurements from the node release's signed policy
(`kms_allowed_mrtd` and `kms_allowed_rtmr0..3` already exist). For this KMS
type the dstack event-log and compose-hash check does not apply: RTMR3 carries
the image's own boot measurement instead.

### Lifecycle

- **Release N:** a node image and a KMS image. MDMA starts a KMS cluster, then
  nodes pointed at it.
- **Upgrade to N+1:** a new node image, a new KMS image, a new cluster, a new
  root. New nodes join their groups and sync from peers. Old nodes are deleted
  and their data disks destroyed.
- **Retire N:** delete the cluster. The root is gone for good, so no copy of an
  old disk can ever be opened again.
- **GCP host maintenance** (`--maintenance-policy TERMINATE`, TDX has no live
  migration): GCP announces maintenance ahead through the `maintenance-event`
  metadata. MDMA starts the replacement first, and it joins before the old VM
  goes. Maintenance windows differ by zone.
- **Any replica lost:** MDMA keeps the count at target, and a replacement joins
  from a surviving peer within minutes.

## Prerequisites

These gaps are tolerable on a node but break "nobody" on a KMS, because a
modified KMS that still attests as genuine would be handed the root:

1. **dm-verity for the root filesystem (#334).** Today `calimero.root_hash`
   is measured only as a cmdline string; nothing re-hashes the files at boot.
   An offline edit of the boot disk keeps the measurements the same. On a KMS
   that edit could print the root after joining. The KMS image must verify its
   rootfs against the measured hash, and should not ship without it. The node
   image needs the same fix.
2. **RTMR3 extension must be fatal.** `calimero-init` only warns when it cannot
   extend RTMR3. The KMS must refuse to serve if its measurement is incomplete.
3. **Refuse debug TDs.** Neither `calimero-tee-attestation` (merod) nor
   mero-kms checks the `TDATTRIBUTES` debug bit today. This gap exists for the
   current fleet too.
4. **No metadata-driven behavior beyond addresses.** The KMS reads only
   `kms-bootstrap` and peer addresses from metadata. Anything else that
   metadata could change (endpoints, policy, flags) would sit outside the
   measurements.

## Trust that remains

- **Intel TDX**, and Intel PCS collateral for quote verification.
- **Google's TDX firmware.** It is measured (MRTD), so a change shows up, but
  it is Google's. Google can stop VMs (availability) but cannot read TD
  memory.
- **The release workflow that builds the image.** It defines what "same as me"
  is. The build is not reproducible today: the base image is pinned to a
  family, and apt installs from live repositories. Until it is, outsiders
  cannot rebuild the image to check its measurements.

## Risks

- **Losing every replica loses the root.** Running nodes keep their keys in
  memory, but a node of that release that restarts cannot reopen its disk. This
  costs node replacements, not data: TEE nodes are `ReadOnlyTee` replicas, and
  even TEE-authored `TeeOnly` writes replicate to every peer.
  - *Unlikely:* 5 replicas in 2 regions, automatic replacement, replacements
    started on maintenance notices, the TCB join rule, a dedicated GCP project
    with deletion protection and alerts on replica count, billing and IAM.
  - *Cheap to recover:* the image holds no secret, so recovery needs no build.
    Start a new cluster from the same release's image (fresh root), start new
    nodes against it, and let them sync. That is the upgrade rollover, triggered
    early. Drill it in staging, including killing every KMS VM.
  - *No backup of the root.* The only real one is a k-of-n split across
    custodians, which turns "nobody" into "k people together". The data already
    lives elsewhere, so it protects nothing sync does not. Losing every node and
    every member's device is covered by admin-readable context backups
    (mdma#365), which add no new reader.
- **Anyone can start a genuine cluster with a different root.** That leaks
  nothing, since the root exists only inside genuine TDs, but nodes pointed at
  it would store data they lose when it stops. The KMS URL comes from metadata,
  so this is an availability risk, not a confidentiality one. Nodes can pin a
  cluster identity (a public key derived from the root) once they have first
  used it.
- **A bug in a released KMS cannot be patched in place.** The fix is the next
  release: new cluster, new nodes.
- **TEE-only secrets must not depend on a release's root.** Core plans
  `TeeSecret<T>` and a namespace TEE vault key: data no member can read. Every
  upgrade here replaces the root, so a vault key derived from it would be lost at
  each release, not only on a KMS loss. The vault key has to pass from old-release
  TEE nodes to new-release ones by attestation, at the protocol level.

## Considered and rejected

- **dstack with an on-chain allowlist and a multisig owner.** The owner can
  still approve code that prints node keys.
- **A frozen dstack app.** `DstackApp` refuses it (`renounceOwnership()`
  reverts), and Phala stays in the trust base.
- **Confidential Space with Cloud KMS.** GCP project and org admins can change
  the key-release policy.
- **Nodes sharing the release root among themselves, with no KMS.** More copies,
  so better availability, but a bug in merod, traefik or mero-auth on any node
  would expose every node's key. A small, separate KMS keeps a node compromise to
  that node.

## Work

| Phase | Where | Work |
| --- | --- | --- |
| 0 | core, mero-kms | Refuse debug TDs in quote verification. |
| 0 | mero-tee | dm-verity rootfs (#334); fatal RTMR3 extension. Both images. |
| 1 | mero-kms | Backend without dstack: configfs-tsm quotes, HKDF from an in-memory root, root-derived transport key, measurements baked in at build time. |
| 2 | mero-kms | Join protocol (mutual attestation, HPKE), bootstrap mode, stateless or sticky challenges. |
| 3 | mero-tee | KMS image: a `kms` role in the playbook, locked profile with the same lockdown as the node, a debug profile for staging. |
| 4 | mero-tee | Release pipeline: build and measure the node image, bake its measurements into the KMS image, build and measure that, then publish the KMS measurements in the node release's signed policy. |
| 5 | core (merod) | Pin a GCP KMS by measurements; no dstack event-log requirement for this type. A generic `kms-url` metadata key alongside `kms-phala-url`. |
| 6 | mdma | Deploy a cluster per release (bootstrap one VM, join the rest, one internal URL); keep the replica count, act on maintenance notices; roll nodes over; recreate a lost cluster; delete old clusters and destroy old disks. |
| 7 | all | Remove the Phala path: `release-kms-phala.yaml`, dstack code in mero-kms, `kms-phala-*` assets, MDMA's Phala provider. |

## Decisions

Made:

- No backup of the root. Losing every replica costs node replacements, and
  admin-readable context backups (mdma#365) cover the loss of every copy of the
  data.
- 5 replicas, 3 zones, at least 2 regions.
- Every upgrade ships new nodes and new keys; nothing re-keys an existing node.
- Phala is removed entirely.

Open:

- Whether the KMS is reachable only inside the VPC.
- Whether a debug KMS profile exists at all, or staging uses the locked one.
- When to remove the Phala path: after the first release served by a GCP
  cluster, or earlier.
