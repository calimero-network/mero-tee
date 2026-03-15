# ADR-0003: Coupled KMS/node version bump guard

- Status: accepted
- Date: 2026-03-15

## Context

Release assets and compatibility metadata depend on synchronized versioning
across:

- `mero-kms/Cargo.toml` (`mero-kms-phala` version),
- `Cargo.lock` package entry for `mero-kms-phala`,
- `mero-tee/versions.json` (`imageVersion`).

Unsynchronized bumps cause release mismatches and downstream verification drift.

## Decision

Keep KMS and node image release version bumps coupled and enforce this with
`scripts/policy/check_release_version_sync.sh` plus CI
(`.github/workflows/release-version-sync-guard.yaml`).

## Consequences

- Prevents partial bumps that break release workflows and compatibility
  expectations.
- Makes release intent explicit in PRs.
- Requires contributors to update all synchronized files in one change.

## Alternatives considered

- Independent version streams per component (rejected for current release
  process complexity and compatibility expectations).
