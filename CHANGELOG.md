# Changelog

All notable changes to this repository are documented in this file.

The format is inspired by Keep a Changelog, and this project follows SemVer tags for release artifacts.

## [Unreleased]

### Added

- **Fleet nodes can serve delegated execution** — a Calimero Cloud account holder who runs no node signs a warrant locally, presents it to a fleet node, and the node executes as *their* principal (the delta is attributed to their account, not the node's). Driven by one new play-level Ansible variable, `fleet_delegated_execution` (on for `debug-read-only` / `locked-read-only`, off for `debug`), which sets **both** edges of the posture: a Traefik router `node-api-intents` exempting `PathRegexp(^/admin-api/contexts/[0-9a-f]{64}/intents$)` (GET/POST/OPTIONS only) from the `auth-node` forwardAuth, and merod's `server.admin.public_intents=true` in `calimero-init`. One variable rather than two role defaults because these nodes run merod in **proxy** auth mode — Traefik is the only gate, so a Traefik exemption without the matching merod setting still opens the path, and the drift would be silent in the unsafe direction. The exempted path is a `PathRegexp` with both ends anchored, not a `PathPrefix` on `/admin-api/contexts/`, which would have exempted every context route including `DELETE`. Exempting it is sound because the request carries its own credential: merod refuses an intent, before executing anything, unless the warrant is genuinely the member's, commits to this exact context/method/arguments, is unexpired, has an unspent nonce, and the node holds `CAN_AUTHOR_ON_BEHALF` on the owning group. **This changes `/etc/traefik/routing.yml` and the merod config, both covered by the image root hash, so the image's measurements change** — intended, since opening a write path is exactly what an attestation policy should notice. `traefik-routing.yml` moved from `files/` to `templates/traefik-routing.yml.j2` accordingly. Requires a core carrying `server.admin.public_intents` and `GET .../intents`.

- **Fleet sidecar reports the three facts a relay client needs**, none of which is derivable off-node: its **executor account** (`meroctl account show` → `accountId`, what a warrant's `executor` must name — an account, not a signing key, so the node re-keying does not void warrants already issued) and its **relay URL** (from the new `relay-url` instance metadata key, since merod terminates no TLS and sits behind an ingress it was never told about, so it cannot derive its own external address) both ride the existing one-second `should-join` poll; and whether it holds **`CAN_AUTHOR_ON_BEHALF`** per namespace (`meroctl group members get-capabilities`, bit 9 / `512`) rides `/api/fleet/confirm` as `authorship_ready`. The capability is **re-read every cycle and re-reported on change** (`reconcile_authorship`, state in `/var/lib/calimero/fleet-authorship.json`), because core implies it from nothing — not membership, not admin, not the subgroup-admit cascade — so a namespace is authorship-closed until an admin publishes the op, typically long after this node was admitted; a join-time answer alone would be frozen at `false` forever and the cloud would never advertise the relay. Only a *change* re-POSTs (the loop runs once a second and `/confirm` is a write), and the recorded state advances only after the POST succeeds, so an MDMA blip is retried rather than lost. Every failure lands on "replicates but does not relay": a missing account, absent `relay-url`, or a failed capability read reports empty/`false`, MDMA then does not advertise the node, and clients are never sent to mint warrants it would refuse. An empty report never erases a value MDMA already holds, so an older and a newer sidecar can be live at once during a roll. Requires an MDMA carrying the matching fields (`executor_account`/`relay_url` on should-join, `authorship_ready` on confirm).

- Feature-gate the mock attestation path in `mero-kms-phala` behind a default-OFF `mock-attestation` feature (forwards to `calimero-tee-attestation/mock-attestation`). Production KMS builds now compile **zero** mock code: `is_mock_quote`/`verify_mock_attestation`, the `ACCEPT_MOCK_ATTESTATION` env read, the measurement-policy skip, and the RTMR3-marker bypass all disappear when the feature is off — verified empirically (`strings` on the release binary finds none of `MOCK_TDX_QUOTE_V1`/`ACCEPT_MOCK_ATTESTATION`/`mock_attestation_rejected`). Test builds pass `--features mock-attestation`. Companion to core #3269.

### Changed

- **Cut image `2.3.52`** (`mero-tee/versions.json` `imageVersion` `2.3.51` → `2.3.52`, with `mero-kms/Cargo.toml` and `Cargo.lock` in sync per the release-version-sync guard). Required, not cosmetic: the delegated-execution work edits `/etc/traefik/routing.yml` and `/usr/local/lib/calimero/init.sh`, both covered by the image root hash, so the MRTD and RTMR3 of a relay-enabled image differ from `2.3.51`'s. `2.3.51` is released and immutable and its `published-mrtds.json` describes the old content, so shipping this under the old version would leave every MRTD-gated allowlist pointing at measurements no node reports — the "bump baked merod ⇒ bump imageVersion" convention (#176), applied to a baked-content change rather than a baked-binary one.

- **`merodVersion` is now a release blocker for read-only profiles, enforced at build time.** It is still pinned at `0.11.0-rc.17`, which predates `server.admin.public_intents` and `GET /admin-api/contexts/<ctx>/intents`, so the new conformance assertion in the `merotee` role **fails the image build** for any profile with `fleet_delegated_execution` on. That is deliberate. Left as a comment, the failure mode is far worse and silent: the image builds, boots, joins namespaces and reports itself to MDMA, and a pre-feature merod simply ignores the unknown config key and 404s the discovery read — so the relay is advertised and never answers, surfacing in a browser days later as "the relay does not respond". The probe asks the baked binary whether `merod init` has `--public-intents`, which needs no node, network or config.

  **To unblock:** bump `merodVersion` to a core release carrying that flag (the change is on core's `master`, unreleased at time of writing) — or build with `-e fleet_delegated_execution=false` for a fleet that only replicates.

  **That bump is a coordinated network upgrade, not a routine pin move — read this before making it.** `merodVersion` is `0.11.0-rc.17`, and the latest core release is `0.11.0-rc.32`. Verified by ancestry against the `0.11.0-rc.17` tag (`23cf02c9`), the jump crosses six breaking wire changes, every one of them absent from rc.17 and present in rc.32:

  | Change | PR |
  | --- | --- |
  | `CrdtType` borsh tags moved to `0x80+` | #3743 |
  | `Custom(String)` → `Custom(CustomTypeId)` digest, new tag | #3789 |
  | **map entries reordered value-first** | #3796 |
  | entries gained a `crdt_type` stamp | #3799 |
  | every `Mergeable` type must declare how it merges | #3807 |
  | admitters became an authorization boundary; endorsement moved onto the envelope | #3804, #3819 |

  Five of the six announce themselves — they move a discriminant, so a stale peer hits an unknown tag and fails the decode. **The map-entry reorder does not.** `Entry<(K, V)>` became `Entry<(V, K)>`: same fields, same length, no tag, so a pre-upgrade reader takes the value bytes for the key and carries on, surfacing as a decode error or as plausible nonsense. And the handshake versioning that would have refused an incompatible peer was removed in #3811 rather than left looking functional, so there is **no in-band detection** — core's own note says the upgrade order is a convention the code does not enforce.

  So the fleet and its clients have to move together, and the cheapest way to pay that once rather than twice is to make a **single** jump to the first core release that also carries delegated execution: rc.32 would cost the same flag-day and still leave this build blocked, since the feature is not in it either.

  Until then the fleet stays on rc.17 deliberately. That is 15 releases stale, which is its own problem — it is recorded here rather than fixed silently, because choosing when to take the flag-day is an operational decision, not a version-file edit.

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

