# Changelog

All notable changes to this repository are documented in this file.

The format is inspired by Keep a Changelog, and this project follows SemVer tags for release artifacts.

## [Unreleased]

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

