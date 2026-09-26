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

- A cluster is 3 or more KMS VMs across zones.
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
MRTD and RTMR0–3, with an up-to-date TCB. There is no allowlist, no config and
no owner. The only code that can ever hold the root is the code already
holding it.

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
  migration): a terminated VM restarts and rejoins from its peers.

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
3. **No metadata-driven behavior beyond addresses.** The KMS reads only
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
  memory, but no node of that release can reopen its disk after a reboot. Its
  data then has to come back from peers by sync. This is the cost of "nobody":
  any backup of the root is someone who can read it. Mitigations: 3 or more
  replicas in separate zones, and monitoring of replica count.
- **Anyone can start a genuine cluster with a different root.** That leaks
  nothing, since the root exists only inside genuine TDs, but nodes pointed at
  it would store data they lose when it stops. The KMS URL comes from metadata,
  so this is an availability risk, not a confidentiality one. Nodes can pin a
  cluster identity (a public key derived from the root) once they have first
  used it.
- **A bug in a released KMS cannot be patched in place.** The fix is the next
  release: new cluster, new nodes.

## Work

| Phase | Where | Work |
| --- | --- | --- |
| 0 | mero-tee | dm-verity rootfs (#334); fatal RTMR3 extension. Both images. |
| 1 | mero-kms | Backend without dstack: configfs-tsm quotes, HKDF from an in-memory root, root-derived transport key, measurements baked in at build time. |
| 2 | mero-kms | Join protocol (mutual attestation, HPKE), bootstrap mode, stateless or sticky challenges. |
| 3 | mero-tee | KMS image: a `kms` role in the playbook, locked profile with the same lockdown as the node, a debug profile for staging. |
| 4 | mero-tee | Release pipeline: build and measure the node image, bake its measurements into the KMS image, build and measure that, then publish the KMS measurements in the node release's signed policy. |
| 5 | core (merod) | Pin a GCP KMS by measurements; no dstack event-log requirement for this type. A generic `kms-url` metadata key alongside `kms-phala-url`. |
| 6 | mdma | Deploy a cluster per release (bootstrap one VM, join the rest, one internal URL); roll nodes over; delete old clusters and destroy old disks. |
| 7 | all | Remove the Phala path: `release-kms-phala.yaml`, dstack code in mero-kms, `kms-phala-*` assets, MDMA's Phala provider. |

## Decisions needed

- Accept losing a release's keys if every replica goes down at once, in
  exchange for nobody holding a copy.
- Replica count and zones, and whether the KMS is reachable only inside the
  VPC. Nodes run with no service account and no public KMS dependency.
- Whether a debug KMS profile exists at all, or staging uses the locked one.
- When to remove the Phala path: after the first release served by a GCP
  cluster, or earlier.
