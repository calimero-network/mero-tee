# ADR-0002: Release policy source of truth and promotion model

- Status: accepted
- Date: 2026-03-15

## Context

Attestation policy values (MRTD/RTMR/TCB allowlists) must be reviewed,
versioned, and reproducible. Ad-hoc runtime variables are hard to audit and can
drift from release artifacts.

This repository already publishes signed release artifacts and maintains
`policies/index.json` plus per-tag policy records.

## Decision

1. Promotion is PR-governed: staged probe outputs are reviewed and committed to
   policy files (`policies/kms-phala/<tag>.json`, `policies/mero-tee/<tag>.json`)
   and `policies/index.json`.
2. Release automation consumes versioned policy files as source of truth.
3. Runtime/policy scripts operate on signed release artifacts and versioned
   policy records rather than mutable, undocumented variable sets.

## Consequences

- Better auditability (who changed policy and why is in git history).
- Easier incident response and rollback by tag.
- More explicit release governance; fewer hidden runtime knobs.

## Alternatives considered

- Pure env-variable policy management (rejected: poor traceability and higher
  operator drift risk).
