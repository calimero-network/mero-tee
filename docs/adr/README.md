# Architecture Decision Records (ADRs)

This directory stores durable decisions that affect security, release process,
or long-lived repository architecture.

## Purpose

Use ADRs to capture:

- the context/problem,
- the decision made,
- the consequences/trade-offs.

ADRs are not design brainstorm notes. They should document decisions that are
already accepted (or explicitly superseded).

## Index

- [ADR-0001: KMS profile pinning and override policy](0001-kms-profile-pinning-and-override-policy.md)
- [ADR-0002: Release policy source of truth and promotion model](0002-release-policy-source-of-truth.md)
- [ADR-0003: Coupled KMS/node version bump guard](0003-version-sync-guard-and-coupled-bumps.md)

## ADR format

Recommended sections:

1. Status
2. Context
3. Decision
4. Consequences
5. Alternatives considered (optional)

When changing behavior governed by an ADR, update the ADR status to
`superseded` and add a replacement ADR.
