# KMS policy auto pipeline

Status: historical design note. There is no dedicated
`kms-phala-policy-auto-pipeline.yaml` workflow in this repository today.

## Purpose

Describe the intended automation model for policy probe + promotion after a
`mero-kms-phala` version bump.

## Current implementation path

- Run `.github/workflows/kms-phala-staging-probe.yaml` to collect candidates.
- Promote reviewed values via PR updates to:
  - `policies/kms-phala/<tag>.json`
  - `policies/index.json`
- Release publication remains driven by `release-kms-phala.yaml` after policy
  PR merge.

## Intended end-state (if reintroduced as a dedicated workflow)

1. Resolves target `mero-kms-phala` version from Cargo metadata.
2. Skips if:
   - policy registry entry already exists, or
   - an open promotion PR already exists for that tag.
   If release already exists but policy entry is missing, it still backfills the
   missing policy PR.
3. On fresh version bumps, waits for `release-kms-phala.yaml` run on the
   same commit (push mode) before probing.
   For release-backfill cases (release exists but policy is missing), it skips
   this wait and proceeds directly.
4. Dispatches `kms-phala-staging-probe.yaml` (using `ghcr.io/<owner>/mero-kms-phala:edge`).
5. Waits for probe completion.
6. Opens/updates a policy PR from probe outputs.

The auto pipeline would create/update the policy PR; release publication would
still occur via `release-kms-phala.yaml` after the policy PR is merged.
