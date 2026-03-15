# ADR-0001: KMS profile pinning and override policy

- Status: accepted
- Date: 2026-03-15

## Context

`mero-kms-phala` supports profile-specific attestation policy cohorts
(`debug`, `debug-read-only`, `locked-read-only`).

Production safety depends on deterministic profile selection. Allowing runtime
overrides of profile on a profile-pinned image can silently mix trust cohorts.
An empty pinned profile marker can also cause unintended fallback behavior.

## Decision

1. If the pinned profile file exists but is empty, KMS startup fails.
2. If image profile pinning is active, `KMS_POLICY_PROFILE` override is rejected
   (even if it matches the pinned value).
3. Default profile resolution without pinning remains explicit and validated.

## Consequences

- Stronger guarantee that deployed image profile and runtime policy profile are
  aligned.
- Reduced risk of operator/config drift across security cohorts.
- Slightly stricter startup behavior (misconfigured environments fail fast).

## Alternatives considered

- Allow matching override value when pinned (rejected: encourages hidden
  configuration dependence and weakens invariants).
