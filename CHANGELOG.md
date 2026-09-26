# Changelog

All notable changes to this repository are documented in this file.

The format is inspired by Keep a Changelog, and this project follows SemVer tags for release artifacts.

## [Unreleased]

### Security

- **Node releases publish a Sigstore bundle for every signed asset.** `published-mrtds.json`, `release-provenance.json`, the SBOM and the checksums now ship a `.bundle.json` beside their `.sig`/`.pem`, as the KMS release already did. The bundle carries the Rekor inclusion proof that lets a verifier check the short-lived signing certificate offline, which is what core needs to verify `published-mrtds.json` when a namespace's TEE admission policy trusts signed releases instead of pasted measurement lists. `verify-generated-signatures.sh` checks the bundles in the release job. Releases published before this carry only `.sig`/`.pem`, so signed-release admission works for nodes on releases from this one on.

- **Nodes pin the KMS's compose hash, and releases always publish one** ([#338](https://github.com/calimero-network/mero-tee/issues/338)). A node's keys are a pure function of the KMS's dstack **app** key and `{namespace}/{profile}/{peerId}`, so anything running under that app ID can derive them outside mero-kms — including the app owner after upgrading the app to a compose file with a shell. merod (core) now replays the KMS's RTMR3 event log from `/attest`, recomputing every event digest, and refuses a KMS whose `compose-hash` is not in the signed policy's `kms_allowed_event_payload`; a policy without one is refused. So `Release mero-kms` now **fails** instead of warning when a profile's probe yields no compose hash, and when two profiles share one (the profile is part of the compose file). `verify-kms-phala-release-assets.sh` requires a non-empty, well-formed `kms_allowed_event_payload`, and `generate-`/`apply-merod-kms-phala-attestation-config.sh` carry it into `config.toml` as `tee.kms.phala.attestation.allowed_compose_hashes` (**needs a merod with that key**). The deploy runbook now requires one dstack app ID per profile and an on-chain compose-hash allowlist holding only the released hash for the locked app, with the owner key in a multisig. The trust model documents the derivation root and a considered, not yet adopted, node-contributed secret with its migration path.

- **mero-kms-phala now releases keys only sealed** (`MERO_KMS_REQUIRE_SEALED_KEY_RELEASE` defaults to `true`, and the compose template sets it explicitly so it is part of the attested compose hash). A `/get-key` request without `sealToB64` — from a merod older than 0.11.0-rc.47, which cannot unseal — is refused with `400 invalid_attestation_request` instead of getting the key in the clear, where whatever terminated TLS in front of the KMS could read it. Nodes on an image older than 2.3.72 can no longer fetch keys from a KMS of this release; recreate them on the current image.

- **mero-kms-phala verifies its release policy's Sigstore signature** (#337). The KMS fetched `kms-phala-attestation-policy.<profile>.json` and enforced its `node_allowed_*` lists without checking its signature, and the optional `MERO_KMS_POLICY_SHA256` pin was never set by the compose template, so anyone able to replace a release asset could choose which node measurements get storage and disk keys. The KMS now fetches the asset's `.sig` and `.bundle.json` and verifies them the way merod does: Rekor signed entry timestamp, detached signature over the exact bytes, and a Fulcio certificate for `calimero-network/mero-tee` / `Release mero-kms` / `push` / `refs/heads/master`. A missing or non-verifying signature leaves the policy unloaded, so `/get-key` fails closed with `503 policy_not_ready`; the legacy fallback asset is never tried instead. The KMS needs to reach `tuf-repo-cdn.sigstore.dev` for the Sigstore trust root. Tests verify the real v2.3.71 policy end to end against the public-good trusted root and refuse the same policy with an extra `node_allowed_mrtd` entry.

- **Node forwardAuth no longer trusts client-supplied `X-Forwarded-*` headers** (mero-tee#339). The `auth-node` middleware had `trustForwardHeader: true`, so Traefik passed the client's own `X-Forwarded-Uri`/`X-Forwarded-Method` to mero-auth's `/auth/validate`. mero-auth checks scoped tokens against that route, so a token scoped to one route could reach another by naming the first. The flaw was latent, because no scoped tokens are issued on these nodes today. It is now `false`, so Traefik sets those headers from the real request. The new `scripts/ci/tests/traefik-forward-auth-test.sh` and a `locked-read-only` conformance assert pin it.

- **`fetch_secret.sh`'s `gcp` provider works on `locked-read-only`** (mero-tee#339). It shelled out to `gcloud`, which is a snap on the GCP Ubuntu base image and cannot run with snapd masked. It now gets an access token from the metadata server and reads Secret Manager's REST API with `curl` and `python3`. It accepts the same secret-name forms, prints the same bytes, and keeps the access token out of `curl`'s argv. The unused `aws` provider is removed: nothing selects it, and the AWS CLI was never installed on the image (the snap-based `common-tools` role is not in the playbook). Conformance asserts that `curl` and `python3` do not resolve into `/snap` and that neither installed copy of `fetch_secret.sh` calls a cloud CLI. The new `scripts/ci/tests/fetch-secret-rest-test.sh` runs both copies against a stub metadata server and Secret Manager, with `gcloud`/`aws` as tripwires.

- **The data disk is encrypted as a whole (LUKS2 with integrity), keyed from the KMS.** The store's own KMS key (below) left everything else on the data disk in plaintext on a device the cloud project can snapshot and rewrite: `config.toml`, blobs, the node's TLS private key, mero-auth's database and the fleet sidecar's token. `calimero-init` now formats a **blank** data disk as LUKS2 (`aes-xts-plain64`, `--integrity hmac-sha256`, so an offline edit fails to read instead of decrypting into garbage merod acts on), with a key from the new `merod kms disk-key` — released by mero-kms-phala only to an attested TD, exactly like the store key. The key exists only in a dedicated tmpfs and is shredded once the disk is open (and on any exit). The disk-unlock identity lives in a `calimero-kms-identity` LUKS2 token: not secret by design, since it obtains nothing without a genuine TD. The volume is opened on every boot by `calimero-init`, never via fstab.

  **Nothing that holds data is ever formatted.** Only a device `blkid -p` positively reports as blank is formatted, and it is re-probed immediately before. A LUKS disk is reopened from its token; a **plain ext4 disk (every node created before this) is mounted exactly as before with a loud WARN** — recreate those nodes to encrypt them; any other signature, a partition table, a failed probe, a LUKS header without our token (an interrupted first boot) or an opened volume without ext4 stops the boot instead. The decision mirrors the store's: `locked-read-only` refuses to create a plaintext data disk (no `kms-phala-url`, or no `merod kms disk-key`/cryptsetup), a KMS URL without `tee-release-version` is refused on every profile, and debug profiles fall back to plain ext4 and say so. `ephemeral-store` is unchanged. **The first boot is slow**: the integrity wipe covers the whole device. `--integrity-no-wipe` would skip it at the cost of integrity errors on reads of never-written sectors, which is the worse failure; `calimero-init.service` gets `TimeoutStartSec=infinity` so the wipe is never killed halfway.

  **Requires a core release with `merod kms disk-key`** and a `merodVersion` bump. Until then a new build-time conformance assert (plus one for cryptsetup and the `dm_crypt`/`dm_integrity` modules) fails `locked-read-only` image builds, deliberately — the alternative is an image on which every new node refuses to boot. Covered by the new `scripts/ci/tests/calimero-init-disk-encryption-test.sh`, which runs the disk block against stub cryptsetup/blkid/mount/merod in 17 disk scenarios and 10 release-floor cases, and is wired into `ci-workflow-lint`.

- **`tee-release-version` can no longer downgrade the KMS policy.** It is instance metadata, and every release's policy is validly signed, so naming an old release whose allowlists accept a since-rejected KMS build was a downgrade anyone who sets metadata could perform. The image now bakes its own version into `/etc/calimero/min-tee-release-version` (measured with the rest of `/etc/calimero`; `image_version` is passed from packer's `version`, i.e. `imageVersion`). `calimero-init` refuses an older release before anything is fetched, and writes/exports `MERO_TEE_MIN_VERSION` for merod, which enforces it with semver. The floor is safe because the KMS release that admits an image is always cut after that image is measured. On `locked-read-only` it also sets `MERO_TEE_PROFILE=locked-read-only` so merod refuses a policy for another profile — not on the debug profiles, because merod fetches the release's default policy asset, which is the locked-read-only policy for every node profile. **The baked floor makes `/etc/calimero` differ per image version, so every release's root hash (and RTMR[2]) now differs even when nothing else changed.**

- **`POST /admin-api/tee/fleet-join` is no longer reachable without authentication.** The traefik router `node-api-tee` exempted `PathPrefix(/admin-api/tee)` from `auth-node`, which covered core's *protected* `fleet-join` (a state change) as well as the two public routes; with merod in proxy auth mode, traefik is its only guard. The router now matches exactly `GET /admin-api/tee/info` and `POST /admin-api/tee/attest`; anything else falls to `node-api`. The fleet sidecar is unaffected: `meroctl --home` talks to merod on loopback directly.

- **Log hygiene (logs ship to an operator-chosen endpoint).** mero-auth no longer runs with `--verbose`; traefik logs at `INFO` instead of `DEBUG`, keeps no access log, and no longer serves its unauthenticated dashboard/API on `:8080`; mero-auth binds `127.0.0.1:3001` instead of every interface (traefik is its only client).

- **Nothing from memory persists on the boot disk.** journald is `Storage=volatile` and not forwarded to syslog; core dumps are off at every layer (`kernel.core_pattern=|/bin/false`, `fs.suid_dumpable=0`, `DefaultLimitCORE=0`, `LimitCORE=0` on merod and mero-auth, systemd-coredump stores nothing and its socket is masked, apport/whoopsie purged); no swap is configured, `swap.target` is masked on `locked-read-only`, and `calimero-init` disables any active swap before fetching a key (and refuses to continue on `locked-read-only` if it cannot). `calimero-init`'s and the sidecar's log files moved from `/var/log` to `/run/calimero`. The sidecar's state, including `fleet-token`, moved from `/var/lib/calimero` (boot disk) to `/mnt/data/fleet` (encrypted data disk); `calimero-init` moves existing state on the first boot and shreds the old copies. merod, mero-auth and the sidecar now `Require` `calimero-init`, so none of them writes to `/mnt/data` (i.e. the root filesystem) when the disk failed to unlock.

- **`locked-read-only` lockdown extended.** Masked: `google-shutdown-scripts`, the GCP guest agent (`google-guest-agent`, `google-guest-agent-manager`) and `google-osconfig-agent` (the packages stay, for their `/dev/disk/by-id/google-*` udev rules), cloud-init's newer `cloud-init-main`/`cloud-init-network` units, rsyslog, apt's periodic timers and snapd, plus every installed unit in those families whatever the base image calls it; unattended-upgrades is purged. `console=` is now stripped from the `grub.d` drop-ins too (the GCP base sets `console=ttyS0` in `50-cloudimg-settings.cfg`, which the old task never saw), so the boot log no longer goes to the operator-readable serial port. **This changes the kernel command line, so `locked-read-only` RTMR[2] changes.** `calimero-init` refuses to download merod at boot on `locked-read-only` (a downloaded binary is in no measurement). Conformance now checks `LoadState=masked` rather than `is-enabled` output, so a lockout unit that is merely absent (and would come back with a package) fails instead of passing, and asserts that no unit in the masked families is left startable, plus the journald/core-dump/swap/console/traefik/mero-auth settings above.

- **New nodes get a KMS-encrypted store, and `locked-read-only` never creates a plaintext one.** TDX protects the VM's memory, not its disks. Until now `calimero-init` ran a plain `merod init` onto a plain ext4 data disk and never configured the KMS: mdma stamped `kms-phala-url` into instance metadata and nothing read it. So merod's store sat in plaintext on a device the host reads. That store holds the node's signing identity (the key it was admitted under as a `ReadOnlyTee`), its account root, and every context's replicated state. A snapshot of the data disk was therefore a copy of an admitted fleet member, able to pull every group key the node held.

  `calimero-init` now reads `kms-phala-url` and creates new nodes with `merod init --kms-url`. The storage key is fetched from mero-kms-phala **before** anything is written, so the identity and account root are never on disk in plaintext. It has to happen at `init`: a store written in plaintext cannot later be opened encrypted, because every read is decrypted. The KMS derives the key from `{namespace}/{profile}/{peerId}`, so it survives image upgrades within a profile. The KMS URL comes from untrusted metadata, and that is fine: merod verifies the KMS's own attestation against the signed release policy named by `tee-release-version`. That makes `tee-release-version` mandatory whenever a KMS is used, and an unverifiable KMS is refused.

  - **`locked-read-only` fails the boot rather than create a plaintext node** when `kms-phala-url` is missing or the baked merod has no `init --kms-url`. A build-time conformance assert catches the second case before release. A KMS-encrypted node with no `tee-release-version` also refuses to start.
  - **Debug profiles** still create a plaintext node without a KMS, and log it.
  - **Nodes created before this keep running and log that their keys must be treated as exposed.** Encrypting them in place cannot work, and would not un-expose keys that have already sat on the disk. Recreate them.

  **Requires a core release with `merod init --kms-url`** ([calimero-network/core#4062](https://github.com/calimero-network/core/pull/4062)) and a `merodVersion` bump. Until then the new conformance assert fails `locked-read-only` image builds, deliberately. Covered by `scripts/ci/tests/calimero-init-store-encryption-test.sh`, which runs the decision against a stub merod in ten cases and is wired into `ci-workflow-lint`.

### Fixed

- **The 2.3.72 node image failed to build on every profile**: Ansible refused `merotee/tasks/main.yml` ("failed at splitting arguments, either an unbalanced jinja2 block or quotes") because the dm-crypt/dm-integrity probe added in #335 had an apostrophe in a shell *comment*, and a free-form `shell: |` string is split into key=value arguments. The comment is reworded, and `ci-workflow-lint` now runs `ansible-playbook --syntax-check` for every profile, so a task file that cannot load fails the PR instead of a packer build (and the KMS release that waits on the image's measurements).

- **Releases build again: the measurement VM keeps its store in memory.** The KMS-store rule above made `locked-read-only` refuse to boot without `kms-phala-url`, and the release pipeline's measurement VM has none. It cannot, because a release's KMS is published only after its image has been measured, so `calimero-init` failed, merod never served `/admin-api/tee/attest`, and "Release mero-tee" failed at "Collect TEE info" for the rc.45 image. The release and staging-probe VMs now set `ephemeral-store=true`. `calimero-init` then mounts a tmpfs over `/mnt/data` and may create the store without a KMS, but only after checking from the mount table that the home really is on tmpfs and no swap is active. The metadata key alone relaxes nothing. Instance metadata is not measured, so the image's published MRTD/RTMRs are unchanged. Three new cases in `calimero-init-store-encryption-test.sh`.

### Changed

- **`fleet_delegated_execution` is now `fleet_delegated_access`, matching core's rename of the flag it drives.** Core renamed `--public-intents` to `--delegated-access` when the flag grew to decide more than two intent routes — it now also decides whether merod's guard accepts a request-carried proof, which reaches reads, and `GET /admin-api/namespaces` executes no intent. This repo's variable name followed.

  **The build-time conformance probe now accepts either flag spelling, and that is required rather than lenient.** Core kept `--public-intents` as a **clap alias**, and a clap alias is *hidden from `--help`* — so the probe sees exactly one of the two names, and which one depends on the release pinned: a merod before the rename lists `--public-intents`, one after lists `--delegated-access`. Asserting either name alone would fail against half the releases that implement the feature perfectly well. Accepting both preserves what the assert is actually for: catching a `merodVersion` pinned at a release with no delegated execution at all, which lists neither. Tighten it to `--delegated-access` once `merodVersion` is past the rename and the alias is dropped upstream.

  **`calimero-init` deliberately still writes `server.admin.public_intents=true`**, and moves last. Core added a serde alias on the config key, so the old spelling is read correctly by a new merod — but the reverse is not true: an *old* merod handed the *new* key ignores it, finds no `public_intents`, defaults to `false`, and silently replicates without relaying. No error, because a missing optional key is not an error. The old spelling is the one that works against both, so it stays until `merodVersion` is guaranteed past the rename.

### Added

- **Staging probe can check a real Secret Manager fetch** (`secret_fetch_check` on `node-image-gcp-staging-probe.yaml`, off by default). It boots the node with a service account, `logs-secret-name` set to a one-off secret, and `logs-endpoint` set to a throwaway receiver VM that records only whether each log push carried the secret's token. A locked node has no shell, so this is how the #339 `fetch_secret.sh` fix is shown to work on a real image. It needs the `GCP_PROBE_SECRET_SA` repo variable and Secret Manager permissions for the workflow's identity; see the runbook. `scripts/ci/tests/node-secret-fetch-probe-test.sh` covers the receiver and the verdict locally.

- **Fleet nodes ask named admitters for admission directly, instead of only broadcasting.** A fleet node used to be admitted only by announcing its attestation on the namespace's gossip topic and waiting for an admin or admitted TEE to hear it; when the only such peer is an owner's laptop behind a relay, that mesh may never form and the node retries into silence. `join_group()` now passes each assignment's `admitter_addrs` from `should-join` (fleet nodes already serving the namespace, then the owner's node) as `meroctl tee fleet-join --admitter-addr`, and core asks them over a stream and gets a verdict back. The sidecar's poll also reports `swarm_addrs` — merod's external addresses, each made to end in `/p2p/<its peer id>` — so MDMA can hand this node to the next joiner. The flags are only passed when the baked `meroctl` lists `--admitter-addr`, so an image on an older merod keeps joining by broadcast rather than failing every join on an unknown flag. Needs a core release carrying `fleet-join --admitter-addr` and an MDMA that returns `admitter_addrs`; against either older side it degrades to exactly the old behaviour. Covered by `scripts/ci/tests/fleet-sidecar-direct-admission-test.sh`.

- **The fleet sidecar reports per-namespace storage bytes to MDMA.** Each namespace in the `/api/fleet/inventory` post now carries `bytes: {state, private_state, delta, governance, total}` from merod's `GET /admin-api/usage`, which nothing consumed until now. It's read once per scan over loopback with no token, the same way `/admin-api/tee/attest` is, because merod runs in proxy auth mode. The values are RocksDB estimates that drift with every write, so they're **excluded from change detection** and refresh on the next post that happens anyway (at worst the 15-minute full pass). If `/usage` is unreachable, or a breakdown is missing a column, `bytes` is omitted rather than sent as zero, and the report is otherwise unchanged. An older MDMA ignores the field. Covered by checks 13–17 in `scripts/ci/tests/fleet-sidecar-inventory-test.sh`.

- **Every ingress router is rate limited, first in its chain.** Until now this ingress had three middlewares — `cors`, `auth-node`, `metrics-auth` — and **none of them limited anything**, while two routers deliberately serve callers holding no credential at all. `node-api-intents` and `node-api-admit` are exempt from `auth-node` because the request carries its own authority, which is what makes both features reachable for the keyholders they exist for; the cost is that anyone can make a node verify signatures, and the routers' own comments called that a request-rate surface "worth watching" with nothing watching it. Two tiers: `rate-limit-public` (20/s, burst 40) on exactly those two routes, far above any real client — a delegated caller signs a warrant and submits it, it does not stream — and `rate-limit` (100/s, burst 200) on everything else, generous enough that it can never trip during ordinary use, because a limit that fires on real traffic gets read as a node fault and raised blindly.

  **The limit is first in every chain, and that ordering is the load-bearing part.** Traefik runs middlewares in order, so a limit placed after `auth-node` pays for a forwardAuth subrequest on every flooded request — a flood of the node becomes a flood of its auth service too, and the middleware meant to prevent that is what schedules it. `scripts/ci/tests/traefik-rate-limit-test.sh` asserts both properties and **pins the router count**, so adding a router without a limit fails the build rather than shipping an unlimited route; it is wired into `ci-workflow-lint` and was mutation-tested against a reordered chain and an added router.

  `sourceCriterion` is set explicitly although the value matches the default. These VMs terminate their own TLS and see the real client address, so per-IP is per-caller — but put a load balancer or CDN in front and every request arrives from one address, at which point the per-IP limit silently becomes a global one and the fleet throttles itself under normal traffic. Whoever adds that hop has to change this block, and an explicit value is what makes it visible enough to change. Traefik counts in memory per instance, one instance per node, so a limit bounds one node rather than the fleet — the right granularity, since the resource being protected is this node's CPU.

  **Note on measurement.** This edits `/etc/traefik/routing.yml`, which the entry above describes as "covered by the image root hash". The root-hash shell in `mero-tee/playbook.yml` hashes `/etc/calimero`, `/usr/local/lib/calimero`, `/etc/default/grub` and the three baked Calimero binaries — `/etc/traefik/` is in none of them, and neither is the traefik binary. Whether MRTD covers it by another route is an open question being tracked privately; until it is answered, a security-relevant ingress change may not be reflected in this image's measurements at all.

- **The sidecar registers with MDMA, binding what it reports to an attested quote** ([mdma#225](https://github.com/calimero-network/mdma/issues/225)). Everything a node said about itself over the fleet API — peer id, executor account, relay URL, MRTD — was authenticated by a fleet-wide token that identifies *some* node and never *which* node. So `should_join` compared a **reported** MRTD against a customer's `allowed_measurements` (a hex string the caller types, making that allowlist satisfiable by assertion rather than by measurement), and relay identity was overwritable by claiming a peer id — which buys denial of service and disclosure of intent contents, since `relay_url` is what clients are routed to. `GET /api/fleet/nodes/challenge` → `POST /api/fleet/nodes/register` closes both. **Nothing signs anything and no core change was needed**: the executor account is minted inside the TEE and never leaves it, so the binding rides the quote's report data — the sidecar computes `SHA256(challenge | peer_id | executor_account | relay_url)`, asks merod's unauthenticated `POST /admin-api/tee/attest` for a quote over that nonce, and MDMA recomputes the same hash from the request body, so a quote commits to exactly one identity and one challenge. State in `/var/lib/calimero/fleet-registration.json`, written **only after MDMA accepted**, and re-registered on identity change rather than on a timer (a registration does not expire; the identity is fixed unless the node re-keys or moves behind a different ingress). MDMA's `503` — the quote could not be *evaluated*, as opposed to `403`, a verdict against this node — is retried rather than recorded, because treating an Intel collateral outage as a refusal would leave a healthy fleet permanently unregistered. Until registration succeeds the node **replicates but does not relay**, the same posture every other failure here takes. Covered by `scripts/ci/tests/fleet-sidecar-registration-test.sh` (7 behaviours against stubbed `curl`), which runs in `ci-workflow-lint`.

- **merod bumped to `0.11.0-rc.35` (image 2.3.56), for the quote verifier MDMA calls.** rc.35 carries exactly one functional change over rc.34 — [core#3925](https://github.com/calimero-network/core/pull/3925), the `calimero-tee-verify` binary — and that binary is what makes the attested registration this repo now performs actually mean anything. The sidecar produces a quote; MDMA has to *verify* it, and its manager is Python, so it shells out to this binary (`tee_verify_binary`). Without it in a released image, `POST /api/fleet/nodes/register` answers `503` — the quote could not be evaluated — for every node, forever. The sidecar handles that correctly (it retries rather than recording a refusal, so nothing breaks), but nothing is enforced either: the measurement allowlist stays a claim rather than a measurement until this bump ships. `imageVersion` moves with `merodVersion` because merod is measured into the image, so a new binary is a new MRTD and needs its own image version rather than silently changing what 2.3.55 means; `mero-kms/Cargo.toml` and `Cargo.lock` follow, per the release-version-sync guard.

- **merod bumped to `0.11.0-rc.34` (image 2.3.55), and the dependency is now asserted rather than assumed.** The sidecar's recovery-envelope writer (mdma#223) shells out to `meroctl account seal-to`, which arrived in core#3918 and ships for the first time in rc.34; the pin was still rc.33, so the image ran a writer whose one external call did not exist. `imageVersion` moves with it — as in #207 (rc.8 to rc.13) — because merod is measured into the image, so a new binary is a new MRTD and needs its own image version rather than silently changing what 2.3.54 means. `mero-kms/Cargo.toml` and `Cargo.lock` follow, per the release-version-sync guard.

  A build-time conformance assert now probes the baked `meroctl account --help` for the `seal-to` subcommand, mirroring the existing `--public-intents` assert for delegated execution and gated the same way the sidecar is (`merod_mode == "read-only"`). The two failures have the same shape — pin a core release predating the feature and the image still builds, still boots, and the sidecar still runs — but this one fails *safe*, which is exactly why it needed asserting: `seal_for_account` just logs a WARN and writes nothing, so no envelope is ever written and the gap surfaces when someone loses their last device and finds there is nothing to recover from, the one moment at which no retroactive fix exists. A failed build naming the release to bump to is a much cheaper place to learn it. The bump alone would have fixed today; the assert is what stops the next stale pin doing it again.

- **Fleet nodes can serve delegated execution** — a Calimero Cloud account holder who runs no node signs a warrant locally, presents it to a fleet node, and the node executes as *their* principal (the delta is attributed to their account, not the node's). Driven by one new play-level Ansible variable, `fleet_delegated_execution` (on for `debug-read-only` / `locked-read-only`, off for `debug`), which sets **both** edges of the posture: a Traefik router `node-api-intents` exempting `PathRegexp(^/admin-api/contexts/[0-9a-f]{64}/intents$)` (GET/POST/OPTIONS only) from the `auth-node` forwardAuth, and merod's `server.admin.public_intents=true` in `calimero-init`. One variable rather than two role defaults because these nodes run merod in **proxy** auth mode — Traefik is the only gate, so a Traefik exemption without the matching merod setting still opens the path, and the drift would be silent in the unsafe direction. The exempted path is a `PathRegexp` with both ends anchored, not a `PathPrefix` on `/admin-api/contexts/`, which would have exempted every context route including `DELETE`. Exempting it is sound because the request carries its own credential: merod refuses an intent, before executing anything, unless the warrant is genuinely the member's, commits to this exact context/method/arguments, is unexpired, has an unspent nonce, and the node holds `CAN_AUTHOR_ON_BEHALF` on the owning group. **This changes `/etc/traefik/routing.yml` and the merod config, both covered by the image root hash, so the image's measurements change** — intended, since opening a write path is exactly what an attestation policy should notice. `traefik-routing.yml` moved from `files/` to `templates/traefik-routing.yml.j2` accordingly. Requires a core carrying `server.admin.public_intents` and `GET .../intents`.

- **Fleet sidecar reports the three facts a relay client needs**, none of which is derivable off-node: its **executor account** (`meroctl account show` → `accountId`, what a warrant's `executor` must name — an account, not a signing key, so the node re-keying does not void warrants already issued) and its **relay URL** (from the new `relay-url` instance metadata key, since merod terminates no TLS and sits behind an ingress it was never told about, so it cannot derive its own external address) both ride the existing one-second `should-join` poll; and whether it holds **`CAN_AUTHOR_ON_BEHALF`** per namespace (`meroctl group members get-capabilities`, bit 9 / `512`) rides `/api/fleet/confirm` as `authorship_ready`. The capability is **re-read every cycle and re-reported on change** (`reconcile_authorship`, state in `/var/lib/calimero/fleet-authorship.json`), because core implies it from nothing — not membership, not admin, not the subgroup-admit cascade — so a namespace is authorship-closed until an admin publishes the op, typically long after this node was admitted; a join-time answer alone would be frozen at `false` forever and the cloud would never advertise the relay. Only a *change* re-POSTs (the loop runs once a second and `/confirm` is a write), and the recorded state advances only after the POST succeeds, so an MDMA blip is retried rather than lost. Every failure lands on "replicates but does not relay": a missing account, absent `relay-url`, or a failed capability read reports empty/`false`, MDMA then does not advertise the node, and clients are never sent to mint warrants it would refuse. An empty report never erases a value MDMA already holds, so an older and a newer sidecar can be live at once during a roll. Requires an MDMA carrying the matching fields (`executor_account`/`relay_url` on should-join, `authorship_ready` on confirm).

- **Fleet sidecar reports the context inventory**, the producer `POST /api/fleet/inventory` never had (mdma#222). The endpoint, the `relay_contexts` table it writes and the `GET /api/cloud/contexts/{id}/relays` read that consumes it all shipped together; the node-side reporter did not, so that route answered `servable: false` for **every** context that exists, and `member_count`/`context_count` stayed `NULL` forever. `reconcile_inventory` now walks each confirmed namespace's group tree breadth-first from the root (the namespace is itself a group and holds contexts of its own) via `group subgroups` / `group contexts list`, and reports each context under **its own group id** with `authorship_ready` re-asked per group — never inherited from the namespace, because core does not propagate `CAN_AUTHOR_ON_BEHALF` through the subgroup-admit cascade and a client would otherwise learn the truth by minting a warrant, which spends a nonce it cannot get back. `member_count`/`context_count` are aggregated **on the node**, inside the group's key, so no account id crosses the wire; an unreadable count is omitted rather than sent as `0`. Posts **on change** with a `full` reconcile every 15 minutes and immediately on a membership change — core exposes no "contexts changed" signal, so the walk is polled once a minute rather than at the loop's 1 Hz, and an incremental post can only add, so the periodic full pass is the only thing that can ever *remove* a context. **A `full` post is claimed only for namespaces whose walk came back complete**: `full` makes MDMA prune every row it does not mention, so a report assembled from partial reads would delete rows for contexts the node is serving and un-advertise a healthy relay. A failed or unparseable read, or a list returned at core's 100-row page limit (`meroctl` passes no offset/limit, so a full page is indistinguishable from a truncated one), demotes that namespace to an additive post. Deliberately narrow: only a read that could hide a *context* demotes — a failed capability or member-count read degrades to `false`/absent without blocking the prune, or a namespace whose member list merely exceeds one page could never be pruned at all. State in `/var/lib/calimero/fleet-inventory.json`, advanced only after a POST MDMA acknowledged. Covered by `scripts/ci/tests/fleet-sidecar-inventory-test.sh` (12 checks against stubbed `meroctl`/`curl`), which runs in `ci-workflow-lint`.

- Feature-gate the mock attestation path in `mero-kms-phala` behind a default-OFF `mock-attestation` feature (forwards to `calimero-tee-attestation/mock-attestation`). Production KMS builds now compile **zero** mock code: `is_mock_quote`/`verify_mock_attestation`, the `ACCEPT_MOCK_ATTESTATION` env read, the measurement-policy skip, and the RTMR3-marker bypass all disappear when the feature is off — verified empirically (`strings` on the release binary finds none of `MOCK_TDX_QUOTE_V1`/`ACCEPT_MOCK_ATTESTATION`/`mock_attestation_rejected`). Test builds pass `--features mock-attestation`. Companion to core #3269.

### Fixed

- **Fleet relays no longer offer an interactive login at all.** A relay is Calimero-operated and serves several tenants' namespaces at once, so nobody should hold a username/password on one — `[providers] user_password` is now `false`, and no new token can be minted on the box. Nothing on the node depended on it: the fleet sidecar calls `http://127.0.0.1:<port>/admin-api/...` directly and `meroctl` uses the local `--home`, so neither crosses Traefik's `auth-node` forwardAuth. What closes is external access to `/jsonrpc` and `/admin-api/` through the ingress, which had no legitimate user on this machine. `mero-auth` starts cleanly with an empty provider set (`create_providers` collects enabled registrations into a `Vec` and returns it unconditionally), and token *validation* is unaffected — there is simply no way to obtain a new one.

- **The relay image advertised a login its binary cannot perform.** `mero-auth-config.toml` carried `near_wallet = true` and a `[near]` block pointing at NEAR testnet. `mero-auth` implements exactly one provider — `crates/auth/src/providers/impls/user_password.rs` — and `AuthConfig.providers` is a `HashMap<String, bool>`, so naming any other one parses cleanly and then matches nothing. The `[near]` block was discarded just as quietly: `AuthConfig` has no `deny_unknown_fields` and no `near` field, so serde dropped it without a word. Nothing was reachable through it and nothing changes at runtime; what is removed is a config file that told an operator reading `/etc/calimero/auth.toml` — or anyone auditing what a fleet relay accepts — that these nodes take wallet logins. `user_password` is deliberately left alone: whether a Calimero-operated relay should accept username/password login at all is a posture question, not the removal of something inert. The file is measured into the image, so the measurement moves with it and this ships with the next image version rather than forcing one.

- **`${#arr[@]}` in the sidecar template broke every node-image release, and then every KMS release behind it.** Jinja opens a comment with `{#`, which is the first two characters of bash's array-length form. `fleet-sidecar.sh.j2` started counting arrays in [#267](https://github.com/calimero-network/mero-tee/pull/267), so from that commit on Ansible read line 735 as a comment-open, scanned to EOF for a `#}` that does not exist, and failed the render with `Missing end of comment tag`. Neither 2.3.55 nor 2.3.56 ever produced a node image.

  Three things kept it hidden for two releases. The sidecar task is `when: merod_mode == "read-only"`, so the `debug` profile built green beside the two that died. The break needs a GCP VM and five minutes of packer to reach, so it surfaces only in the release workflow, never on a PR. And the four `fleet-sidecar-*-test.sh` harnesses do substitute the template's variables — with `sed`, which proves the bash is right and asks nothing about whether Jinja can parse the file.

  It then propagated: `Release mero-kms` refuses to publish without `mero-tee-v<version>/published-mrtds.json`, which only a successful node-image release writes. So every push to master after the bump failed with `NODE_RELEASE_MISSING` — a message naming an absent release rather than the broken template three jobs upstream.

  The render is fixed by moving Jinja's comment delimiter to `{@#`/`#@}` on that one task, which costs nothing (the template has no Jinja comments, only two variables) and retires the whole class for this file rather than escaping four call sites. `scripts/ci/check-ansible-templates.py` is the part that keeps it fixed: it parses every template with the delimiters its own `template:` task declares — not the defaults, since a task may legitimately move them — and runs in `ci-workflow-lint`, which already triggers on `mero-tee/**`. A template no task renders is also an error, so nothing can sit unchecked. Reverting the delimiter fix makes it report `fleet-sidecar.sh.j2:735: Missing end of comment tag`, the same line and message the packer log gave, in about a second.

- **The docs-update guard demanded documentation for changes that have none to write.** It decided purely by path: any file under `.github/workflows/**` required a `docs/**`, `README.md` or `CHANGELOG.md` edit in the same PR. A Dependabot action pin bump is one line — `uses: actions/setup-node@v6` to `@v7` — and tripped the identical rule as rewriting a release job, so the only way to merge one was to write a changelog line that says nothing. Eight such PRs were open at once, the oldest ([#208](https://github.com/calimero-network/mero-tee/pull/208)) since July: #208, #214, #195, #196, #141, #140, #132, #129. That is both supply-chain staleness — these are the actions that build and sign our images — and a good way to teach everyone that this guard is noise, which it is not about real workflow changes.

  A workflow file whose diff touches **only `uses:` lines** is now exempt. Content-based and deliberately narrow: change one line that is not a `uses:`, in the same file or another, and the guard re-arms. The other trigger paths (`scripts/release`, `scripts/policy`, `scripts/attestation`, `scripts/kms`, `scripts/ci`, `mero-tee/**`) are untouched, so a version bump like #272's still needs its changelog entry.


- **The post-release probes did not re-run when the scripts that decide their verdicts changed.** Both post-release workflows filter on a path list that named the workflow and its top-level script but none of the probe scripts those actually run. So merging #264 -- which changed `scripts/ci/probes/node_runtime_kms_probe.sh`, the probe whose broken expectation logic #264 existed to fix -- triggered nothing, and the fix landed without re-validating anything. Merging #263 did re-run the node e2e only because it happened to touch `e2e-mero-tee-node-post-release.sh`, which was on the list; the same commit's change to the KMS-node workflow produced a 14-second run whose real steps were all skipped.

  Both lists now also carry the probe workflow that gets dispatched and the three scripts that decide what it asserts (`assert_node_anti_fake.py`, `node_anti_fake_http.py`, `node_runtime_kms_probe.sh`). Generic plumbing -- logging, summary writers, polling helpers -- is deliberately left off: these workflows boot real TDX VMs and Phala CVMs, so they should re-run when the verification logic changes, not when a log line does. The principle is recorded as a comment in both files, since the next person adding a probe script will face the same question.

  Verified by parsing both workflows and checking, for each, that no verification-bearing file is missing from its path list, that the `push` and `pull_request` lists are identical, and that every declared path exists on disk.

- **The node->KMS runtime probe ran merod unprivileged, so the cross-profile check reported a KMS refusal it never observed.** `node_runtime_kms_probe.sh` SSHes in and runs `merod ... kms probe`, but merod's home is the root-owned encrypted TEE mount and the systemd unit runs it as root, while `gcloud compute ssh` logs in unprivileged. Without `sudo` merod cannot read the node dir and exits from a `bail!` that fires before printing any JSON, so all twelve attempts fell through to the non-JSON fallback and the probe recorded `MEROD_KMS_PROBE_NO_JSON`. The sibling anti-fake check carried exactly this fix until #255 replaced it with the HTTP path and deleted that script, taking the fix with it; this invocation was left behind unprivileged.

  Surfaced on 2.3.53 as `KMS_PROBE_EXPECTATION_MISMATCH` on `profile=debug` (run 34637264907), which then failed the KMS-node compatibility run waiting on it (#262). The published artifacts were not affected.

  **The mismatch was the lucky outcome.** `expected_code_matches` defaults to true when `KMS_PROBE_EXPECTED_CODES` is unset, and a merod that cannot start yields `ok=false`, which an expected-failure outcome accepted as a match. So with no expected codes configured this probe would have **passed vacuously** -- asserting that the locked KMS correctly refused a debug node when merod never reached the KMS at all. Only the explicit codes list turned that silent pass into a visible failure.

  So `sudo` is restored *and* a no-result is no longer allowed to stand in for a refusal: `MEROD_KMS_PROBE_NO_JSON` never satisfies an expected failure, because an expected failure is a claim about what the KMS did, and a probe that produced nothing readable did not observe the KMS doing anything. This is the same rule #255 set for the anti-fake check's `inconclusive` and #263 kept in its asserter -- failing to establish a property is not evidence for it. The specific recognized `MEROD_TEE_NOT_CONFIGURED` path is unchanged and still counts.

  Verified by extracting the script's real matching block and running it over six probe/expectation combinations: merod-never-started with and without expected codes (the first of which passed before this change and now fails with a warning naming why), a genuine KMS refusal, the `MEROD_TEE_NOT_CONFIGURED` path, a debug node wrongly *accepted* by the locked KMS, and an expected success -- confirming the three legitimate passes still pass and only the unobserved ones now fail. `bash -n` clean; shellcheck reports only the pre-existing SC1091 note about the sourced logging helper.

- **Post-release anti-fake assertions read a shape no producer emits, so both post-release probes could never pass.** #255 moved the node's client-side anti-fake verification from SSH (`merod tee probe`, the node grading itself) to HTTP (`node_anti_fake_http.py`, CI choosing the nonce and Intel Trust Authority returning the verdict), renaming every field in the result. The two consumers were not updated, and each carried its **own copy** of the assertions -- `scripts/release/e2e-mero-tee-node-post-release.sh` and the inline block in `post-release-kms-node-e2e.yaml` -- so the same stale block broke in two places at once. All four assertions read keys that do not exist: `checks.positive.passed` (no producer; split into `nonce_binding` + `genuine_hardware`), `checks.wrong_nonce.rejected` and `checks.tampered_quote.rejected` (the producer emits `.passed`), and `checks.wrong_expected_application_hash.rejected` (no producer anywhere).

  Caught on 2.3.53, the first release where the corrected probes ran against a published artifact: both post-release workflows failed *after* logging `OK: probed node measurements exactly match published policy`, and reported `checks.positive.passed expected true, got None` -- an error naming the assertion rather than the drift, and reading like a failed security property rather than a missing key. The published artifacts were never affected; only their independent post-release verification was. Filed automatically as #261 and #262 by the mechanism added in #257, which is why this surfaced in minutes rather than across two releases like #251.

  Both copies are replaced by one shared `scripts/ci/probes/assert_node_anti_fake.py`, so the producer and the assertion cannot drift apart in one place but not the other. It checks the result's **shape before its verdicts**: a renamed or dropped check now fails naming the checks it expected *and* the ones actually produced, instead of a `None` that looks like a security failure. It also cross-checks the producer's own `outcome` / `failed_checks` against the per-check booleans and refuses to pass when they disagree, and keeps #255's rule that only an explicit pass counts -- an `inconclusive` ITA result (transport failure, 5xx) fails rather than passes, since failing to establish a property is not evidence for it.

  `wrong_expected_application_hash` is **dropped rather than silently passed**: the HTTP probe has no equivalent check, so there is nothing to read. If that property still needs covering it belongs in `node_anti_fake_http.py` as a real check -- its own change, not an assertion here that can only ever be None.

  Verified by driving the asserter over seven result shapes: a healthy node (all four pass), ITA declining the quote, an inconclusive tamper check, per-check passes contradicted by the producer's summary, the pre-#255 SSH-era shape (the exact payload 2.3.53 hit -- now reporting the drift by name), an absent `checks` object, and an unreadable file. Both call sites were then run verbatim as the shell invokes them. `bash -n` and shellcheck clean; the workflow YAML parses.

  Not fixed here: the node staging probe's own `KMS_PROBE_EXPECTATION_MISMATCH` on `profile=debug` (run 34637264907), which is what failed the KMS-node compatibility run downstream. That is the optional node->KMS runtime probe #255 left on SSH, and a separate cause.

- **Base image `ubuntu-2510-amd64` → `ubuntu-2604-lts-amd64`, unblocking every node-image build.** All three "Build and attest" profiles (`debug`, `debug-read-only`, `locked-read-only`) were failing identically at the `Validate Packer source image` preflight with *"Source image family ubuntu-2510-amd64 not found in ubuntu-os-cloud"* — before any GCP instance was created, which is why all three failed the same way. Nothing in this repository changed: 25.10 (Questing) is an **interim** release, reached EOL in July 2026, and Canonical delists an EOL release from `ubuntu-os-cloud`, taking its image family with it. So the pin broke on the calendar. An LTS is used now rather than another interim precisely so this does not recur in nine months; 26.04 LTS is also comfortably past the kernel 6.17+ that RTMR3 sysfs support needs, and `calimero-init.sh.j2` already reads the newer `tdx_guest/measurements/` layout with a fallback to `tdx_guest/mr/`, so it needs no change. The Ansible role carries no release-specific assumptions to update either — no `questing` apt sources, and `linux-modules-extra-{{ ansible_kernel }}` is resolved at build time.

  **The base change moves the image's measurements**, which is handled by the pipeline rather than by hand: `published-mrtds.json` is generated per release by booting the built image and reading its quote, and `compatibility-catalog.json` points each release at its own policy URL. No allowlist is edited here. Nodes pinned to an earlier release keep using that release's image and policy.

  **The published image name and family deliberately do NOT move.** They still read `merotee-ubuntu-questing-25-10-<profile>-<version>` / `merotee-ubuntu-questing-<profile>`, because mdma's dispatcher resolves images by those exact prefixes (`tee_image_name_prefix` / `tee_image_family_prefix` in `dispatcher/app/config.py`) and so does `scripts/release/node-image-gcp/resolve-image-vm-parameters.sh`. Renaming them in this repo alone would leave the dispatcher unable to find any image, so it needs a paired mdma change and a deploy ordering. Until then the name is an identifier, not a statement about the base release — said so in `ubuntu.pkr.hcl`, in `resolve-image-vm-parameters.sh`, and in all three docs pages, since an image built on 26.04 and named `questing-25-10` is otherwise just misleading. The `image_description` **is** corrected, as nothing parses it.

  **The pin now has one home.** `ubuntu.pkr.hcl`'s `source_image_family` is the single source of truth, and CI's preflight reads it out of that file instead of repeating the literal. That duplication was a latent bug of its own: the gate and the build could check different bases, and the gate is the thing meant to catch a bad pin. The preflight also now prints the families `ubuntu-os-cloud` actually publishes when the pin is missing, so the next delisting names its own fix rather than a command for someone to go and run. Verified by extracting the step's script from the workflow YAML and running it against the real `ubuntu.pkr.hcl` under four stubbed `gcloud` outcomes — family present (exit 0, reads `ubuntu-2604-lts-amd64` / `ubuntu-os-cloud`), family absent with a listable project (exit 1, prints the families), family absent and unlistable (exit 1, prints the fallback line), and a missing `ubuntu.pkr.hcl` (exit 1 with the annotation, which needed an explicit `-f` guard — without it `sed` died under `set -e` and the annotation never printed). `shellcheck` clean on the extracted step and on both touched shell scripts.

- **`ruint` 1.17.2 → 1.20.0 (lockfile only), clearing RUSTSEC-2026-0220.** `cargo audit` reported one vulnerability — "Uint shift operations: incorrect overflow flags and truncated shift amounts", patched in 1.20.0 — and had been failing the scheduled `Security audit` on `master` for five consecutive weeks (2026-08-03 through 08-31). It is not introduced here; it surfaces on this branch because the `security-audit` workflow only runs on a pull request that touches `Cargo.lock` / `Cargo.toml` / `mero-kms/Cargo.toml`, and the `imageVersion` bump above is the first such change since the advisory landed. Fixed rather than deferred, since it is a semver-compatible minor bump inside `^1` needing no manifest change: `cargo update -p ruint`. It locks six new `ark-*` 0.6.0 packages that 1.20.0 lists as optional dependencies; nothing else moves. `cargo audit` now exits 0 with only allowed warnings, and `cargo check --workspace --all-targets` and `cargo test --workspace` (63 tests) pass.

### Changed

- **Cut image `2.3.54`** (`mero-tee/versions.json` `imageVersion` `2.3.53` → `2.3.54`, with `mero-kms/Cargo.toml` and `Cargo.lock` in sync per the release-version-sync guard). This is the first release cut with every post-release check actually working, and it exists to prove that end to end rather than to change what is shipped.

  2.3.53's artifacts were already correct -- its `published-mrtds.json` carries `["uptodate", "outofdate"]` on all three profiles, confirmed against the signed published asset -- but its verification was not. The node post-release e2e only passed against it after #263 landed, and the KMS-node compatibility leg has still never validated it: its run on 2.3.53 failed, and the one after #263 skipped every real step. #264's `sudo` fix has never executed against any release at all. So the invariant `policy_core` subset of `policy_kms` currently rests on a directly-read artifact plus one of the two post-release legs.

  Cutting 2.3.54 runs both release workflows and both post-release probes with all of #254, #255, #256, #257, #259, #263, #264 and the trigger-path fix above in place, which is the only way to exercise them against a genuinely published artifact. `merodVersion` stays at `0.11.0-rc.33` -- decoupled by design, and moving it would change the node binary in the release meant to validate the verification path.

  If a post-release probe fails here, that is the pipeline working: #257 files it as an issue within minutes, which is the difference from the two releases where an inverted TCB allowlist shipped unnoticed.

- **Cut image `2.3.53`** (`mero-tee/versions.json` `imageVersion` `2.3.52` → `2.3.53`, with `mero-kms/Cargo.toml` and `Cargo.lock` in sync per the release-version-sync guard). This one is needed to *correct a published policy*, not to record a content change. `published-mrtds.json` in the `mero-tee-v2.3.52` release carries `allowed_tcb_statuses = ["outofdate"]` for all three profiles, with `uptodate` absent — confirmed by downloading the signed asset, not inferred from source. Enforcement is exact set membership (`get_key.rs:enforce_tcb_status`), so the shipped policy accepts only a stale host and refuses a fully patched one, on both legs of the mutual attestation: the KMS reads `node_allowed_tcb_statuses` to judge node quotes and merod reads `kms_allowed_tcb_statuses` to judge the KMS. Nothing breaks while the whole fleet is behind on microcode; the first host to be patched, or any host newly provisioned on current firmware, is refused its storage key and fails to come up. The fleet was set up to break on being fixed. Every release since at least 2.3.48 shipped it, because the value was copied from whatever the release probe VM observed rather than declared — fixed in this cut by the declared-policy change above.

  `merodVersion` stays at `0.11.0-rc.33`. It is decoupled by design, pinning the core merod tag baked into the image, and moving it would swap the node binary in the same release that corrects the attestation policy — two changes whose effects on the published measurements would then be hard to attribute separately.

  This cut also carries the three fixes that explain why the inverted allowlist survived two releases: post-release node verification moved into CI over `/admin-api/tee/attest` (it previously asked the node to grade itself over SSH, a channel `locked-read-only` removes by design, and ran merod unprivileged against a root-owned TEE mount), the KMS staging probe stopped resolving `kms_tag=latest` through GitHub's latest-release flag, and a failed post-release probe is now filed as an issue instead of leaving a row in the Actions tab. None of the corrected probes has yet run against a *published* release — only against pull requests — so this release is their first live exercise.

- **Cut image `2.3.52`** (`mero-tee/versions.json` `imageVersion` `2.3.51` → `2.3.52`, with `mero-kms/Cargo.toml` and `Cargo.lock` in sync per the release-version-sync guard). Required, not cosmetic: the delegated-execution work edits `/etc/traefik/routing.yml` and `/usr/local/lib/calimero/init.sh`, both covered by the image root hash, so the MRTD and RTMR3 of a relay-enabled image differ from `2.3.51`'s. The bump follows the "bump baked merod ⇒ bump imageVersion" convention (#176), applied to a baked-*content* change rather than a baked-binary one, so that an MRTD-gated allowlist is never left pointing at measurements no node reports. **Correction to an earlier revision of this entry:** it claimed `2.3.51` was "released and immutable". It is not — the newest *published* mero-tee release is `2.3.50` (2026-07-13); `2.3.51` was cut in this changelog but never tagged or released, so no `published-mrtds.json` describes it. The bump is therefore hygiene rather than a hard requirement, and it is kept because one unreleased version per content change is the cheaper convention to hold.

- **`merodVersion` `0.11.0-rc.17` → `0.11.0-rc.33`, taking the coordinated upgrade in one jump.** This unblocks the read-only image build: the `merotee` role's conformance probe asks the baked binary whether `merod init` carries `--public-intents`, and rc.33 is the **first** core release that does. Verified by ancestry rather than by date — core `c521ff54a` (#3828, the commit adding `server.admin.public_intents` and `GET /admin-api/contexts/<ctx>/intents`) is contained in tag `0.11.0-rc.33` and in no earlier rc, and `--public-intents` is present in rc.33's `crates/merod/src/cli/init.rs` and absent from rc.17's.

  `imageVersion` stays at `2.3.52`. Ordinarily a new baked merod means a new image version (#176), but `2.3.52` has never been released — and, because the conformance probe has been failing the build for every relay-enabled profile, no `2.3.52` relay image exists anywhere to have had its measurements published. The content of the unreleased `2.3.52` is simply whatever this PR ships, rc.33 included.

  **The flag-day is larger than an earlier revision of this entry described, and the correction matters.** That revision counted six breaking wire changes between rc.17 and rc.32. Against rc.33 the count is **thirteen**, because the whole governance op-sealing series landed after rc.32:

  | Change | PR |
  | --- | --- |
  | `CrdtType` borsh tags moved to `0x80+` | #3743 |
  | `Custom(String)` → `Custom(CustomTypeId)` digest, new tag | #3789 |
  | **map entries reordered value-first** | #3796 |
  | entries gained a `crdt_type` stamp | #3799 |
  | every `Mergeable` type must declare how it merges | #3807 |
  | admitters became an authorization boundary; endorsement moved onto the envelope | #3804, #3819 |
  | handshake versioning removed | #3811 |
  | registry-only application distribution | #3652 |
  | request bodies refuse unknown fields | #3830, #3842 |
  | **`RootOp::KeyDelivery` is sealed** | #3847 |
  | **the two joins whose publisher holds the namespace key are sealed** | #3850 |
  | **a relayed invitation join is sealed** (`RootRelaySealed`) | #3856 |
  | a replayed root op runs its side effects, bounded | #3854 |

  The sealing series changes the consequence of *not* bumping, and this is the part worth reading twice. It appends variants to `NamespaceOp` and changes which root ops travel sealed, so a namespace driven by current clients now carries `RootSealed` / `RootRelaySealed` ops that **rc.17 cannot decode at all**. Borsh rejects an unknown discriminant outright rather than misreading it, so this fails closed — but it means an rc.17 fleet node is no longer merely *missing a feature* in such a namespace; it cannot follow the governance DAG. **The bump is now a correctness requirement, not only a delegated-execution unblock.**

  The one change that still gives no signal in either direction is the map-entry reorder (#3796): `Entry<(K, V)>` became `Entry<(V, K)>` — same fields, same length, no tag — so a stale reader takes value bytes for the key and carries on, surfacing as a decode error or as plausible nonsense. With the handshake versioning removed in #3811 there is no in-band detection, so **clients and the fleet still have to move together**; that has not changed, and core's own note is that the upgrade order is a convention the code does not enforce.

- Bump the pinned `calimero-network/core` git rev to `23cf02c9` (`0.11.0-rc.17`) — the first published core release carrying the default-off `mock-attestation` feature — and cut release **2.3.51**: `mero-kms/Cargo.toml` `2.3.50` → `2.3.51`, `imageVersion` `2.3.50` → `2.3.51`, `Cargo.lock` in sync per the release-version-sync guard.
- Bump `merodVersion` `0.11.0-rc.13` → `0.11.0-rc.17` in `mero-tee/versions.json` so the GCP node image bakes the rc.17 merod, aligning the fleet with the KMS core dep and rc.17 clients. The governance borsh wire is append-only across rc.13→rc.17 (one new `GroupKeyRotated` `GroupOp` variant appended at the end; envelope enums and schema version unchanged), so an rc.17 fleet node (a ReadOnlyTee that never authors ops) does not reintroduce the rc.8→rc.13-style decode skew — roll clients to rc.17 in tandem to close the one residual (`GroupKeyRotated` from a client self-leaving a Restricted group is unreadable by lagging rc.13 clients).

### Security

- Move `cargo audit` back to green by bumping four advisory-affected dependencies to patched releases (no ignore-list entries needed): `rand` `0.9.2` → `0.9.5` and `0.8.5` → `0.8.6` (RUSTSEC-2026-0097 `ThreadRng` unsoundness), `crossbeam-epoch` `0.9.18` → `0.9.20` (RUSTSEC-2026-0204 invalid pointer deref in the `fmt::Pointer` impl), and `quinn-proto` `0.11.14` → `0.11.16` (RUSTSEC-2026-0185 remote memory exhaustion via unbounded out-of-order QUIC stream reassembly). All are semver-compatible patch bumps in `Cargo.lock` — the pinned core rev is untouched.

- Bump `merodVersion` `0.11.0-rc.5` → `0.11.0-rc.6` and `imageVersion` `2.3.46` → `2.3.47` in `mero-tee/versions.json` (with `mero-kms/Cargo.toml` + `Cargo.lock` kept in sync per the release-version-sync guard) so fleet TEE nodes pick up the core Open-subgroup replication fix (core #2809). `2.3.46` is already released and immutable, so a new image (`2.3.47`) is required to carry the new baked merod tag — mirrors the #176 "bump baked merod ⇒ bump imageVersion" convention. The build downloads `merod_<arch>-unknown-linux-gnu.tar.gz` directly from `github.com/calimero-network/core/releases/download/0.11.0-rc.6/` with no sha256 pin, and the node-image release gate verifies the `0.11.0-rc.6` core tag + its required tarball assets exist, so the image build is BLOCKED until core `0.11.0-rc.6` is actually released.
- Bump `merodVersion` `0.10.1-rc.44` → `0.11.0-rc.5` in `mero-tee/versions.json` so the GCP node image bakes the core merod carrying the TEE-lifecycle work (core #2793: #2772 admission, #2776 key-deletion / Part-1 purge, #2792 emit-after-persist). Couples the new leave-on-disable sidecar (2.3.46) with the new merod into one image for the disable→leave→purge e2e. `imageVersion` stays at `2.3.46` (the image-source change is the baked merod tag, no sidecar/asset change). The build downloads `merod_<arch>-unknown-linux-gnu.tar.gz` directly from `github.com/calimero-network/core/releases/download/0.11.0-rc.5/` with no sha256 pin, so no post-release checksum step is required — but the node-image release gate verifies the `0.11.0-rc.5` core tag + its three required tarball assets exist, so the image build is BLOCKED until core `0.11.0-rc.5` (PR #2793) is actually released.

## [2.3.46] - 2026-06-17

### Added

- Fleet HA sidecar `leave_group()`: when mdma stops assigning a namespace to this node (HA disabled, slot reclaimed, MRTD distrust), the sidecar now runs `meroctl namespace leave <hex_namespace_id>` so core evicts the node from the namespace + all subgroups and purges its local data + keys. Computed as `to_leave = confirmed − desired`, run BEFORE the intersection-prune so the diff is taken while `confirmed` still holds the dropped entries. The call is idempotent / non-fatal: leaving a namespace already left (`nothing to leave` / `not a direct member`) is logged and the loop continues. (Part 2 of 3; the AES key deletion that makes the purge actually shred keys lands in core #2776 / Part 1.)

### Fixed

- Fleet HA sidecar `poll_mdma()`: SAFETY-CRITICAL — no longer swallows curl failures into `{"assignments":[]}`. It now returns 0 + a validated assignments body on HTTP 200, or 1 on any curl error / non-2xx / timeout / unparseable or wrong-shape body (mirrors the `confirm_assignment` 0/1 contract; captures the body and exit status separately). The main loop gates the entire reconcile cycle on a successful poll: on failure it does NOT compute desired, join, leave, or prune, and leaves the `confirmed` file untouched. This prevents a transient mdma outage from looking like "all namespaces disabled" and triggering `namespace leave` (which irreversibly purges keys) on every healthy replica. Preserving `confirmed` across a failed poll is also required for the leave logic: a pruned `confirmed` would hide a genuine disable from the next good poll's `confirmed − desired` diff.

### Changed

- Synchronized release version to `2.3.46` across `mero-tee/versions.json` (`imageVersion`), `mero-kms/Cargo.toml`, and `Cargo.lock` to force a node-image + KMS rebuild carrying the leave-on-disable sidecar. `merodVersion` unchanged at `0.10.1-rc.44` — the merod build carrying core #2776 / Part-1 key deletion is a release-time bump once that core change ships.

## [2.3.43] - 2026-05-16

### Fixed

- Fleet HA sidecar `poll_mdma()`: include this node's own MRTD in the `/api/fleet/should-join` request body (`{"peer_id":...,"mrtd":...}`). MDMA's `should_join` handler skips every MRTD-allowlisted HA request whose `body.mrtd` does not match, and the sidecar previously sent `peer_id` only (`body.mrtd=""`), so no MRTD-gated group was ever assigned and fleet nodes never joined
- Added `get_mrtd()` helper: reads the kernel-exposed TDX measurement at `/sys/class/misc/tdx_guest/measurements/mrtd:sha384` (48 raw bytes, hex-encoded lowercase, no `0x`) — the same value the QE embeds as `quote.mrtd()`, obtained read-only without generating a quote. Verified to return the expected per-image MRTD on a live 2.3.42 fleet node

### Changed

- Synchronized release version to `2.3.43` across `mero-kms/Cargo.toml`, `Cargo.lock`, and `mero-tee/versions.json` to force a node-image + KMS rebuild carrying the fixed sidecar (`merodVersion` unchanged at `0.10.1-rc.34`)

## [2.3.42] - 2026-05-16

### Fixed

- Fleet HA sidecar `wait_for_merod()`: poll `meroctl --output-format json peers` instead of the nonexistent `meroctl health` subcommand (the old probe never exited 0, so the sidecar hung forever at "Waiting for merod..." and never polled `/api/fleet/should-join`)
- Fleet HA sidecar `get_peer_id()`: read the node PeerId from `/mnt/data/calimero/default/config.toml` under `[identity].peer_id` instead of the invalid `meroctl peers list` (`peers` takes no args and returns only a count)

### Changed

- Synchronized release version to `2.3.42` across `mero-kms/Cargo.toml`, `Cargo.lock`, and `mero-tee/versions.json` to force a node-image + KMS rebuild carrying the fixed sidecar (`merodVersion` unchanged at `0.10.1-rc.34`)

## [2.3.41] - 2026-05-16

### Fixed

- Fleet HA sidecar `join_group()`: pass `group_id` positionally to `meroctl tee fleet-join` (core `0.10.1-rc.34` defines it as a positional `GROUP_ID` arg; the previous `--group-id` flag form always failed clap parsing)
- Fleet HA sidecar `join_group()`: capture `rc=$?` immediately instead of `result=$(...) || true` followed by `if [[ $? -eq 0 ]]` (which zeroed `$?` and made every join report success, calling `/api/fleet/confirm` even on failure)
- Removed stale "fleet-join not available yet (core upgrade needed)" `TODO`/`WARN` text — the subcommand ships in the pinned merod `0.10.1-rc.34`

### Changed

- Synchronized release version to `2.3.41` across `mero-kms/Cargo.toml`, `Cargo.lock`, and `mero-tee/versions.json` to force a node-image + KMS rebuild carrying the fixed sidecar (`merodVersion` unchanged at `0.10.1-rc.34`)

## [2.3.31] - 2026-03-30

### Fixed

- Install archive extraction tools (`bzip2`, `xz-utils`, `unzip`) in Ansible role before downloading core binaries

## [2.3.32] - 2026-03-30

### Fixed

- Move archive tools install to playbook `pre_tasks` so they're available before any role (including `mero-traefik`) runs `unarchive`

## [2.3.30] - 2026-03-30

### Changed

- Bump `merodVersion` to `0.10.1-rc.10` (TEE admission policy governance ops, attestation-based auto-admission)
- Bump KMS core dependencies (`calimero-server-primitives`, `calimero-tee-attestation`) to `0.10.1-rc.10`
- Synchronized release version to `2.3.30` across `mero-kms/Cargo.toml`, `Cargo.lock`, and `mero-tee/versions.json`

## [2.3.27] - 2026-03-26

### Changed

- Synchronized release version to `2.3.27` across `mero-kms/Cargo.toml`, `Cargo.lock` (`mero-kms-phala` package), `mero-tee/versions.json` (`imageVersion`), and `compatibility-catalog.json`.

## [2.3.26] - 2026-03-26

### Changed

- Synchronized release version to `2.3.26` across `mero-kms/Cargo.toml`, `Cargo.lock` (`mero-kms-phala` package), `mero-tee/versions.json` (`imageVersion`), and `compatibility-catalog.json`.

## [2.3.25] - 2026-03-26

### Changed

- **Post-release e2e**: tightened probe-vs-published verification from **subset** to **exact equality** for MRTD, RTMR0–2, and TCB status checks across all three workflows (`e2e-mero-tee-node-post-release.sh`, `post-release-kms-node-e2e.yaml`, `e2e-verify-kms-node-compatibility.sh`). Fresh VM / KMS measurements must now match the published release policy exactly, not just be contained within it.
- Synchronized release version to `2.3.25` across `mero-kms/Cargo.toml`, `Cargo.lock` (`mero-kms-phala` package), `mero-tee/versions.json` (`imageVersion`), and `compatibility-catalog.json`.

## [2.3.24] - 2026-03-26

### Changed

- Synchronized release version to `2.3.24` across `mero-kms/Cargo.toml`, `Cargo.lock` (`mero-kms-phala` package), `mero-tee/versions.json` (`imageVersion`), and `compatibility-catalog.json`.

## [2.3.23] - 2026-03-26

### Fixed

- **`post-release-mero-tee-node-e2e`** and **`post-release-kms-node-e2e`**: on `push`, dispatch child probe workflows from the immutable release tag ref (`mero-tee-v*`) instead of `master`; automation commits advancing `master` between the bump push and probe dispatch no longer cause an unexpected-HEAD-SHA failure.
- Extended push-path release poll to ~60 minutes (was ~5 minutes) so the mero-tee e2e verify job waits long enough for **Release mero-tee** to finish.

### Changed

- Synchronized release version to `2.3.23` across `mero-kms/Cargo.toml`, `Cargo.lock` (`mero-kms-phala` package), `mero-tee/versions.json` (`imageVersion`), and `compatibility-catalog.json`.

## [2.3.22] - 2026-03-26

### Fixed

- **`upsert-umbrella-release-links.sh`** (node + KMS): when **Release mero-tee** and **Release mero-kms** run together on the same version bump, concurrent `gh release create` for the semver umbrella tag no longer fails the job; the script reconciles with `gh release edit` if the release already exists.

### Changed

- Synchronized release version to `2.3.22` across `mero-kms/Cargo.toml`, `Cargo.lock` (`mero-kms-phala` package), `mero-tee/versions.json` (`imageVersion`), and `compatibility-catalog.json`.

## [2.3.21] - 2026-03-26

### Changed

- **`post-release-mero-tee-node-e2e`**: verify job runs on **`push` to `master`** (aligned with KMS-node e2e); skips with a summary if the **`mero-tee-v*`** GitHub release is not published yet.
- Synchronized release version to `2.3.21` across `mero-kms/Cargo.toml`, `Cargo.lock` (`mero-kms-phala` package), `mero-tee/versions.json` (`imageVersion`), and `compatibility-catalog.json`.

## [2.3.20] - 2026-03-25

### Changed

- Added **`post-release-mero-tee-node-e2e`** workflow and **`scripts/release/e2e-mero-tee-node-post-release.sh`**: after a successful **Release mero-tee** run, boot fresh GCP TDX VMs per profile and verify probe measurements against **`published-mrtds.json`** without waiting for **mero-kms** (documented in `docs/release/workflow-setup.md`).
- Synchronized release version to `2.3.20` across `mero-kms/Cargo.toml`, `Cargo.lock` (`mero-kms-phala` package), `mero-tee/versions.json` (`imageVersion`), and `compatibility-catalog.json`.

## [2.3.19] - 2026-03-24

### Fixed

- `verify_dstack_compose_hash.py`: compare RTMR3 event-log replay to **RTMR3 from the TD quote** (via `measurements_from_quote`), not ITA JWT fields — Intel Trust Authority claim layout can disagree with the quote blob and caused false replay mismatches in CI.

### Changed

- Reorganized `scripts/attestation/`: **`shared/`** (ITA + policy extraction used by node and KMS), **`kms/`** (compose-hash / Phala-only helpers). Moved Phala deploy assets to **`scripts/kms/phala/`** (was `scripts/phala/`). Updated workflows and docs to match.
- Removed optional local/operator helpers: `patch-release-policy.sh`, `fetch-and-analyze-failed-attestation.sh`, `fetch-and-inspect-phala-probe-event-log.sh`, `verify-compose-hash-flow.sh`, `compare-mdma-node-with-release.sh` (docs updated for manual compare steps).
- Synchronized release version to `2.3.19` across `mero-kms/Cargo.toml`, `Cargo.lock` (`mero-kms-phala` package), `mero-tee/versions.json` (`imageVersion`), and `compatibility-catalog.json`.

## [2.3.18] - 2026-03-24

### Fixed

- `verify_tdx_quote_ita.py`: resolve MRTD from parsed TD quote bytes when ITA JWT claims do not expose mrtd/mr_td-style hex fields; cross-check when both sources exist.

### Changed

- Synchronized release version to `2.3.18` across `mero-kms/Cargo.toml`, `Cargo.lock` (`mero-kms-phala` package), `mero-tee/versions.json` (`imageVersion`), and `compatibility-catalog.json`.

## [2.3.17] - 2026-03-24

### Fixed

- `verify_tdx_quote_ita` / `extract_tdx_policy_candidates`: accept **mero-kms** `/attest` JSON (top-level `quoteB64`) as well as merod `data.quoteB64` (fixes KMS staging probe when `attest-response.json` is from Phala KMS, not merod).

### Changed

- Synchronized release version to `2.3.17` across `mero-kms/Cargo.toml`, `Cargo.lock` (`mero-kms-phala` package), `mero-tee/versions.json` (`imageVersion`), and `compatibility-catalog.json`.

## [2.3.16] - 2026-03-24

### Changed

- Attestation tooling uses merod canonical paths only: prefer `data.quote.body` for measurements, then `data.quoteB64` (no JSON tree scoring). Updated `extract_tdx_policy_candidates.py`, `verify_tdx_quote_ita.py`, and `attestation-verifier` `extractQuote`.
- Synchronized release version to `2.3.16` across `mero-kms/Cargo.toml`, `Cargo.lock` (`mero-kms-phala` package), and `mero-tee/versions.json` (`imageVersion`).

## [2.3.15] - 2026-03-24

### Changed

- Post-release KMS-node e2e: bounded KMS asset wait (~30m) with per-poll logs; heartbeats while waiting on child workflows; no longer require KMS release `targetCommitish` to match the mero-tee tag SHA; `quoteb64` scoring in attestation scripts aligned with merod JSON.
- Synchronized release version to `2.3.15` across `mero-kms/Cargo.toml`, `Cargo.lock` (`mero-kms-phala` package), and `mero-tee/versions.json` (`imageVersion`).

## [2.3.14] - 2026-03-24

### Changed

- **`verify_tdx_quote_ita.py`:** Prints an **ITA CI summary** to stdout (ITA URL, request kind, node quote JSON path, quote length, **SHA-256 of the quote bytes**, JWT claim keys, and **`tdx_mrtd` / `tdx_rtmr0`–`3`** previews from the ITA token). Writes **`ita-ci-verification-summary.json`** next to other verification artifacts. Does not log raw base64 quotes (too large for CI).
- **Node image release:** Attestation probe VMs now default to **`cloud-486420`**, **`europe-west4-a`**, **`c3-standard-4`** when GitHub repo Variables are unset, matching Calimero Cloud MDMA so `published-mrtds.json` RTMR measurements align with dispatcher-created nodes. `resolve-image-vm-parameters.sh` no longer inherits the Packer subnetwork when the attestation project differs from the image project (subnet is auto-discovered in the attestation project). See `docs/release/workflow-setup.md`.
- Synchronized release version to `2.3.14` across `mero-kms/Cargo.toml`, `Cargo.lock` (`mero-kms-phala` package), and `mero-tee/versions.json` (`imageVersion`).

## [2.3.13] - 2026-03-26

### Changed

- Synchronized release version to `2.3.13` across:
  - `mero-kms/Cargo.toml`,
  - `Cargo.lock` (`mero-kms-phala` package),
  - `mero-tee/versions.json` (`imageVersion`).

## [2.3.12] - 2026-03-25

### Fixed

- Phala CVM `name` must not contain dots; version segment is normalized to hyphens
  (e.g. `mero-kms-debug-2-3-11`) in `trigger-staging-probe.sh`, `kms-phala-staging-probe.yaml`,
  and docs. `MERO_KMS_VERSION` in compose remains the real semver.

### Changed

- Synchronized release version to `2.3.12` across:
  - `mero-kms/Cargo.toml`,
  - `Cargo.lock` (`mero-kms-phala` package),
  - `mero-tee/versions.json` (`imageVersion`).

## [2.3.11] - 2026-03-25

### Changed

- KMS Phala staging probe and `trigger-staging-probe.sh`: versioned Phala CVM deployment names aligned with MDMA (see 2.3.12 for Phala-valid naming).
- `docs/attestation/compose-hash-flow.md`: document versioned deployment names.
- Synchronized release version to `2.3.11` across:
  - `mero-kms/Cargo.toml`,
  - `Cargo.lock` (`mero-kms-phala` package),
  - `mero-tee/versions.json` (`imageVersion`).

## [2.3.10] - 2026-03-24

### Changed

- `scripts/attestation/shared/extract_tdx_policy_candidates.py`: when `--attest-response` is set,
  derive MRTD and RTMR0–3 from the TD quote (same layout as `attestation-verifier`); drop
  heuristic scored-walk selection for measurements (canonical ITA keys only if the quote
  path is not used).
- Release and probe workflows pass `--attest-response` into policy candidate extraction.
- Synchronized release version to `2.3.10` across:
  - `mero-kms/Cargo.toml`,
  - `Cargo.lock` (`mero-kms-phala` package),
  - `mero-tee/versions.json` (`imageVersion`).

## [2.1.80] - 2026-03-18

### Fixed

- `post-release-kms-node-e2e` workflow now dispatches probe workflows using
  `${PROBE_WORKFLOW_REF}` (branch ref) instead of a raw commit SHA, fixing
  `HTTP 422: No ref found` dispatch failures.

### Changed

- Synchronized release version to `2.1.80` across:
  - `mero-kms/Cargo.toml`,
  - `Cargo.lock` (`mero-kms-phala` package),
  - `mero-tee/versions.json` (`imageVersion`).

## [2.1.79] - 2026-03-18

### Changed

- Release assets now publish `event_payload` (compose-hash event payload) instead of `kms_compose_hash` in compatibility map and `kms_allowed_event_payload` instead of `kms_allowed_compose_hash` in policy files.
- Removed backwards compatibility for legacy `kms_compose_hash` / `kms_allowed_compose_hash` fields.
- Synchronized release version to `2.1.79` across:
  - `mero-kms/Cargo.toml`,
  - `Cargo.lock` (`mero-kms-phala` package),
  - `mero-tee/versions.json` (`imageVersion`).

## [2.1.51] - 2026-03-15

### Fixed

- `release-kms-phala.yaml`: added missing repository checkout in the `probe` job
  before running modular script helpers (`scripts/release/kms-phala/*.sh`),
  fixing release failures caused by missing script files in CI job workspaces.

### Changed

- Synchronized release version to `2.1.51` across:
  - `mero-kms/Cargo.toml`,
  - `Cargo.lock` (`mero-kms-phala` package),
  - `mero-tee/versions.json` (`imageVersion`).

## [2.1.50] - 2026-03-15

### Added

- Regression test coverage for `mero-kms` config/policy loading, including:
  - strict pinned-profile override rejection,
  - policy JSON role/profile mismatch guards,
  - env-policy loading combinations (`USE_ENV_POLICY`, hash-pin gating, malformed allowlists).
- Lightweight inline documentation in release scripts (`scripts/release/kms-phala/*.sh`,
  `scripts/release/node-image-gcp/*.sh`) and modular KMS code paths.

### Changed

- Enforced strict pinned-profile behavior in `mero-kms`:
  - empty `/etc/mero-kms/image-profile` now fails startup,
  - `KMS_POLICY_PROFILE` override is rejected whenever image profile pinning is active.
- Synchronized release version to `2.1.50` across:
  - `mero-kms/Cargo.toml`,
  - `Cargo.lock` (`mero-kms-phala` package),
  - `mero-tee/versions.json` (`imageVersion`).
- Cleaned/updated docs that referenced missing policy workflows and aligned them with
  current probe/script-driven promotion flow.

## [2.1.49] - 2026-03-14

### Added

- Modular release workflow helper scripts:
  - `scripts/release/kms-phala/*`
  - `scripts/release/node-image-gcp/*`
- New `mero-kms` modules:
  - `src/config.rs`
  - `src/policy.rs`
  - `src/runtime_event.rs`
  - endpoint-split handlers under `src/handlers/`.

### Changed

- Refactored monolithic release workflows into reusable script components:
  - `.github/workflows/release-kms-phala.yaml`
  - `.github/workflows/release-node-image-gcp.yaml`.
- Split `mero-kms/src/main.rs` and `mero-kms/src/handlers.rs` into smaller modules/files
  for maintainability and clearer ownership boundaries.
- Hardened CI compatibility for release scripts (shellcheck/docs-guard alignment).

### Notes

- Earlier entries remain preserved below; this section brings the changelog in sync
  with the current `2.1.49+` release line.

## [2.1.16] - 2026-03-12

### Added

- **Baked merod**: `merod`, `meroctl`, and `mero-auth` are now baked into the image at build time via the `calimero-core` role. No runtime download or `merod-version` metadata required for new images.
- `merodVersion` in `versions.json` (core tag, e.g. `0.10.0`). CI uses `GATED_MEROD_VERSION` when set.

### Changed

- `calimero-init` uses baked binaries if present; falls back to runtime download (requires `merod-version` metadata) for legacy images.

## [2.1.15] - 2026-03-07

### Added

- `mero-tee` init now reads `tee-release-version` metadata and writes `/etc/calimero/merod.env` with `MERO_TEE_VERSION=<value>` when set.

### Changed

- `merod.service` now loads optional runtime overrides via `EnvironmentFile=-/etc/calimero/merod.env`.

## [2.1.14] - 2026-03-06

### Added

- KMS fetches attestation policy from official release at boot when `MERO_KMS_VERSION` is set, instead of trusting env vars. Use `USE_ENV_POLICY=true` for air-gapped deployments.

### Changed

- MDMA passes `MERO_KMS_VERSION` when creating KMS deployments so the KMS fetches policy from `https://github.com/calimero-network/mero-tee/releases`.

## [2.1.13] - 2026-03-06

### Added

- Formal release taxonomy and operator-facing documentation index.
- Release verification, policy-promotion, and signed trust artifact workflows.

## [2.1.4] - 2026-03-04

### Added

- Signed locked-image trust artifacts (`published-mrtds.json`, policy, provenance, checksums).
- Signed KMS trust assets (checksums, manifest, attestation policy).
- Policy registry mapping (`policies/index.json`) for KMS and locked-image releases.

### Changed

- Release automation now reads policy mappings from versioned registry entries.

## [2.1.3] - 2026-02-xx

### Added

- Initial `mero-kms-phala` and locked-image release automation in this repository.

