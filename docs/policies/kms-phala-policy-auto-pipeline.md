# KMS policy auto pipeline

Workflow file:

- `.github/workflows/kms-phala-policy-auto-pipeline.yaml`

## Purpose

Automate policy probe + promotion when a new `mero-kms-phala` version is merged
to `master`, so operators do not need to manually dispatch workflows.

## Trigger

- Push to `master` that changes `mero-kms/Cargo.toml`
- Manual fallback via `workflow_dispatch`

## What it does

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
6. Dispatches `kms-phala-policy-promotion-pr.yaml` with the probe run ID and release tag.

The workflow creates/updates the policy PR; release publication still occurs via
`release-kms-phala.yaml` after the policy PR is merged.
