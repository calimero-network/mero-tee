# Changelog

All notable changes to this repository are documented in this file.

The format is inspired by Keep a Changelog, and this project follows SemVer tags for release artifacts.

## [Unreleased]

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

- `scripts/attestation/extract_tdx_policy_candidates.py`: when `--attest-response` is set,
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

