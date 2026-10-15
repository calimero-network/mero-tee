# Design: reproducible images with computed measurements

Status: proposed, for agreement before any code. Tracks mdma#480 (minimal
in-house image), mdma#475 (pin build inputs), mdma#476 (compute RTMR1-3 from
the build) and mdma#477 (independent rebuild), and this repository's #465.
Items marked **prototype question** are not yet known and are what the first
phase has to answer.

Turn "trust the CI run that built and probed the image" into "anyone can
rebuild the release from its tag, get the same bytes, and compute the
measurements the quote must carry, without a TDX VM".

## Why

The KMS is frozen: once an image is built, no party can change which code gets
the root or a node's keys ([gcp-tdx-kms.md](gcp-tdx-kms.md), Decisions). That
moves the remaining lever to whoever controls the build. Today a release's
`published-mrtds.json` holds what one release probe *observed*: the workflow
boots each profile on a GCP TDX VM, reads the quote, and signs the registers.
Nothing ties those registers to the source. A compromised build input or
workflow would produce a release every verifier accepts, and nobody outside
can rebuild it to notice, because the build is not reproducible
([security.mdx](../src/content/docs/understand/security.mdx)).

## Goal

1. **Same bytes.** Two builds of one tag, on different machines and days,
   produce bit-identical image artifacts.
2. **Computed registers.** A tool computes RTMR1, RTMR2 and RTMR3 for each
   image and profile from those artifacts alone. MRTD and RTMR0 are the
   platform's (below) and are published as such.
3. **Probe as a cross-check.** The release still boots each profile and reads
   its quote. A release whose probed RTMR1-3 differ from the computed ones
   fails.
4. **Second signature.** An independent rebuild, under its own identity, must
   reproduce the artifacts and registers and co-sign them (mdma#477).

### Not in scope

- Changing what verifiers check. Core admission, merod's KMS policy and mdma
  keep comparing MRTD and RTMR1-3 (RTMR0 when pinned) for equality, from the
  same `allowed_*` fields. Only how the values are produced changes.
- Platforms other than GCP TDX. The design should not preclude bare-metal TDX,
  but its firmware (MRTD) and RTMR0 handling is a later document.
- dstack. Its KMS is ruled out by the frozen-KMS decision; borrowing its
  Apache-2.0 measurement code is allowed.

## How images are built today

What the design replaces, as of `master` at 2.3.117:

| Step | Today | Reproducible? |
| --- | --- | --- |
| Base | Packer `googlecompute` boots `source_image_family = "ubuntu-2604-lts-amd64"` (`ubuntu.pkr.hcl`) | No: a family resolves to whatever image is newest |
| Packages | Ansible `apt` installs from the live Ubuntu archive | No: versions follow the archive |
| Downloaded binaries | merod, traefik, vector, node, mero-bot pinned by sha256 (`build-inputs.lock.json`, #461) | Yes |
| Changes | Applied to the running VM, whose disk becomes the image | No: a booted system carries logs, machine state and timestamps |
| `calimero.root_hash` | Hash over `/etc/calimero`, `/usr/local/lib/calimero`, `/etc/default/grub` and merod (`playbook.yml`), put on the kernel cmdline | Only if every input is |
| Sealed root | `seal-root.sh`: copy the live root to EROFS (`mkfs.erofs -T0`), `veritysetup format`, `roothash=` on the cmdline | No: both tools pick random identifiers unless told otherwise (checked below), so the root partition and the verity root hash differ on every build even for identical files |
| Boot chain | Google's TD firmware → GRUB from the base image's partition → kernel + dracut initrd, cmdline carrying `calimero.root_hash` and `roothash=` | Inherits the above |
| RTMR3 | `calimero-init` extends `SHA-384("calimero-rtmr3-v2:<role>:<profile>:<calimero.root_hash>")` | Computable once the root hash is |
| Measurements | The release probe boots each profile on `c3-standard-4` and publishes the quote's MRTD, RTMR0-3 | Observed, not computed |

Checked with Ubuntu 24.04's `cryptsetup-bin` 2.7.0 and `erofs-utils` 1.7.1
(2026-10-15; the image itself builds on 26.04, whose versions should be
re-checked in phase 0):

- `veritysetup format` on the same 8 MiB input twice gave two different salts
  and root hashes. With `--salt` and `--uuid` fixed, both runs gave the same
  root hash.
- `mkfs.erofs -T0` on the same directory twice gave two different images (the
  filesystem UUID is random). With `-U` fixed as well, both were identical.

What already exists and carries over:

- `scripts/attestation/shared/tdx_event_log.py` parses the CCEL event log,
  replays it into RTMR0-3 and diffs two logs. It was built to diagnose KMS
  joins refused over differing registers.
- mero-kms `/attest` returns its CCEL log on request (`eventLog: true`).
  Core's node `/admin-api/tee/attest` does not, so a node image whose probed
  registers disagree with the computed ones cannot be diagnosed from its quote
  alone. See Work, phase 1.

## Which register measures what

On TDX, firmware maps the TCG PCR an event would have gone to onto a
measurement register: PCR 1 and 7 to RTMR0, PCR 2-6 to RTMR1, PCR 8-15 to
RTMR2, with RTMR3 left to the guest (UEFI `EFI_CC_MEASUREMENT_PROTOCOL`, Intel
TDX virtual firmware design guide). The CCEL log records the register directly
(index 0 is MRTD, 1-4 are RTMR0-3), which is what `tdx_event_log.py` reads.

| Register | Measures | Whose | Approach |
| --- | --- | --- | --- |
| MRTD | The TD firmware, measured by the TDX module | Google's on GCP; identical for every image | Published per platform. Checking it against Google's own statement is mdma#481 |
| RTMR0 | Firmware configuration: virtual hardware, ACPI tables, boot variables | Google's, varies with machine shape | Published per platform and machine type; verifiers already treat it as optional |
| RTMR1 | EFI applications the firmware loads (bootloader, or UKI), and the GPT | Ours | **Computed** |
| RTMR2 | Kernel cmdline and initrd (and, with GRUB, every GRUB command and file it loads) | Ours | **Computed** |
| RTMR3 | `calimero-init`'s `calimero-rtmr3-v2:<role>:<profile>:<root_hash>` event | Ours | **Computed** (already a pure function of role, profile and root hash) |

RTMR3 is extended from public inputs, so it names the image only together with
RTMR1 and RTMR2. That rule does not change; this design makes RTMR1 and RTMR2
computable so the rule can be checked from source.

## Design

### 1. Build offline from pinned inputs

Replace "boot a VM and change it" with an offline image build that never runs
the image it produces:

- **Builder: mkosi**, with the same distribution (Ubuntu 26.04 LTS) so package
  behaviour does not change at the same time as the build.
- **Packages from a snapshot.** Install from `snapshot.ubuntu.com` at a
  timestamp recorded in the repository, so a rebuild sees the same archive.
  Package signatures are still checked against Ubuntu's keys.
- **Everything else stays sha256-pinned** in `build-inputs.lock.json`.
- **The build environment is pinned too:** mkosi version, and the builder's
  own base image, recorded in the release's provenance.
- **No live state.** `SOURCE_DATE_EPOCH` is fixed from the release commit, and
  machine-id, SSH host keys, logs and caches are excluded or generated at
  first boot, never baked.
- **Deterministic filesystem identifiers.** EROFS with a fixed timestamp
  (`-T`) and a fixed UUID (`-U`), and `veritysetup format` with an explicit
  `--salt` and `--uuid`, all derived from the release (for example, a hash of
  the tag and profile). Without them the root hash differs between builds of
  identical files (checked above).
- **Output:** a raw GPT disk image plus a checksum manifest (`SHA256SUMS`) of
  every artifact the boot chain reads: firmware-loaded EFI binaries, kernel,
  initrd, cmdline, root and verity partitions. The **image digest** is
  `sha256(SHA256SUMS)`.
- **GCE upload:** `gcloud compute images create` from the raw disk (UEFI and
  TDX guest features set), replacing the Packer snapshot. **Prototype
  question:** confirm GCE does not rewrite any byte the boot chain measures
  (for example the GPT), and record the uploaded object's hash.

The three profiles (`debug`, `debug-read-only`, `locked-read-only`) and three
roles (`node`, `kms`, `agent`) stay separate images built from the same
pipeline, with role- and profile-specific package sets and config.

### 2. Boot chain: GRUB or a unified kernel image

Which components land in RTMR1 and RTMR2, and so how hard they are to compute,
depends on the boot chain. Two options:

| | A. Keep GRUB (as today) | B. Unified kernel image (UKI) |
| --- | --- | --- |
| What firmware loads | Bootloader chain from the base image (shim and GRUB on Ubuntu cloud images; **prototype question:** confirm on the probe's event log) | One signed or unsigned EFI binary: `systemd-stub` + kernel + initrd + cmdline |
| RTMR1 | Each EFI binary's Authenticode hash | The UKI's Authenticode hash |
| RTMR2 | Kernel, initrd, cmdline, and every GRUB command and file GRUB measures, so it depends on the exact `grub.cfg` | The UKI's sections (cmdline, initrd) as `systemd-stub` measures them |
| Parts to make reproducible | shim, GRUB, its modules, `grub.cfg`, kernel, initrd | One file |
| Changes to `seal-root.sh` / initrd | Small | The cmdline (with `roothash=`) moves into the UKI, so the UKI is built after the root is sealed |

**Proposal: B, a UKI**, because it collapses everything we measure before
RTMR3 into one artifact with one hash, and removes GRUB's command-by-command
measurement from RTMR2. dstack's GCP path also boots a UKI.
**Prototype questions:**
- whether GCP's TD firmware boots an unsigned UKI with the Secure Boot setting
  we run, or needs a signed chain;
- exactly which events GCP's firmware and `systemd-stub` emit into RTMR1 and
  RTMR2 for a UKI, read from a probe's CCEL log.

If B does not work on GCP, A is the fallback; it needs every GRUB input pinned
and `grub.cfg` generated deterministically.

### 3. Computing the registers: `mero-tee-mr`

A small tool, alongside `tdx_event_log.py`, that takes the built artifacts and
a **platform event template** and prints MRTD and RTMR0-3 per profile:

1. **The template, recorded once per platform.** From one probe's CCEL log,
   keep every event that does not depend on our image (separators, firmware
   actions, boot-variable events) with its digest, and mark the events that do
   (EFI application, GPT, cmdline, initrd). The template is committed and
   reviewed; a change to it is a visible platform change.
2. **Recompute our events from the artifacts.** Authenticode hash of each EFI
   binary (or the UKI), the GPT as written, and the cmdline and initrd as the
   stub measures them. The RTMR3 event is
   `SHA-384("calimero-rtmr3-v2:<role>:<profile>:<root_hash>")`, with the root
   hash computed from the build.
3. **Replay** template plus recomputed events into RTMR1-3, with the same
   extend rule `tdx_event_log.py` already implements.

The tool needs no TDX hardware and no network beyond the artifacts. It is what
a third party runs. Where practical, it reuses existing Apache-2.0
implementations (dstack's `dstack-mr`) for Authenticode and event formats
rather than writing them again.

**Prototype question:** whether any image-independent event varies between
two boots of the same machine type (for example a boot-variable or ACPI event).
Such an event would belong in RTMR0 by the mapping above; if one lands in
RTMR1 or RTMR2, the template cannot be fixed and the design has to account for
it.

### 4. Release flow

1. Build each role and profile (step 1). Record `SHA256SUMS` and the image
   digest.
2. Compute RTMR1-3 with `mero-tee-mr` (step 3).
3. Upload to GCE and run the existing probe on `c3-standard-4`.
4. **Gate:** the probe's RTMR1-3 must equal the computed ones, and its MRTD and
   RTMR0 must equal the published platform values for that machine type.
   Otherwise the release fails, with the event-log diff attached.
5. Publish `published-mrtds.json` (below), signed as today.
6. The independent rebuild (mdma#477) rebuilds from the tag on a separate
   runner and GCP project, checks it gets the same image digest and registers,
   and publishes its own signature over the same file.

A side effect worth having: the KMS image bakes the node allowlist. Today it has
to wait for the node image's probe; with computed registers it can be built from
the node image's computed values, and the probe gate still runs before either
is released.

### 5. What `published-mrtds.json` gains

Existing `allowed_*` fields keep their names and meaning, so no verifier
changes. Added per profile:

- `image_digest`: `sha256(SHA256SUMS)`;
- `artifacts`: name → sha256 for every measured artifact;
- `measurement_source`: `"computed+probed"`;
- `rtmr3_event`: the exact string extended, for readers who want to recompute
  it by hand.

And per release, a `platform` block: MRTD and RTMR0 per supported machine type,
plus the event template's hash.

## Trust after this

- **Still trusted:** Intel TDX and PCS; Google's TD firmware (MRTD, RTMR0;
  mdma#481); Ubuntu's archive signing keys and the snapshot service; the build
  definitions in this repository, which are now reviewable as code.
- **No longer trusted alone:** a single CI run or its inputs. A tampered input
  changes the artifacts, so the image digest and computed registers no longer
  match an independent rebuild or a third party's.
- **Unchanged:** verifiers, admission, the KMS freeze rule, mdma's image name
  contract (`merotee-*` names and families).

## Risks

| Risk | Effect | Mitigation |
| --- | --- | --- |
| A non-deterministic step we did not find | Builds differ; the gate or the rebuild fails | Build twice in CI on every change (as `inference-proxy`'s `reproducible-build.yml` does); `diffoscope` on any mismatch |
| GCP firmware changes an image-independent event | The computed registers stop matching the probe | Caught by the gate; the template is updated in a reviewed change |
| UKI does not boot under our GCP settings | Option B fails | Fall back to A (GRUB) |
| Moving from Packer to mkosi changes the running system | Node behaviour regressions | Keep Ubuntu 26.04 and the same roles' configuration; run the existing e2e and probe suites against both pipelines for one release |
| Snapshot archive unavailable at rebuild time | Rebuild blocked | Mirror the pinned `.deb`s, by hash, alongside the release |

## Work

| Phase | Where | Work | Done when |
| --- | --- | --- | --- |
| 0 | mero-tee | **Prototype:** build the `node` / `locked-read-only` image with mkosi as a UKI; boot it on a GCP TDX VM; capture its CCEL log | The prototype questions above are answered in this document |
| 1 | core | Optional `eventLog` on node `/admin-api/tee/attest`, as mero-kms has | The probe stores each profile's CCEL log |
| 2 | mero-tee | Pinned, offline, deterministic build for all roles and profiles (#475) | Two CI builds on different runners produce the same image digest |
| 3 | mero-tee | `mero-tee-mr` and the platform template (#476) | Computed RTMR1-3 equal the probe's for every profile |
| 4 | mero-tee | Release gate (computed = probed) and the new `published-mrtds.json` fields | A release fails on any mismatch |
| 5 | mero-tee, new identity | Independent rebuild and co-signature (#477, #465) | Verifiers can require both signatures |
| 6 | mero-tee | Retire the Packer pipeline | One release shipped from mkosi only |

## Decisions needed

- Boot chain: UKI (proposed) or GRUB, after the prototype.
- Base distribution: Ubuntu 26.04 via mkosi (proposed), or another.
- Where the independent rebuild runs, and under which identity.
- Whether verifiers should start requiring the second signature by default once
  phase 5 lands, or opt in per namespace.
