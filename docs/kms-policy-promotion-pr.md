# KMS policy promotion workflow (PR)

This workflow promotes a previously collected staging probe artifact into a
reviewable pull request that updates versioned policy files in this repository.

Workflow file:

- `.github/workflows/kms_policy_promotion_pr.yaml`

## Purpose

`kms_staging_probe_phala.yaml` collects **candidate** values from a staged CVM.
This workflow turns those candidates into a PR so policy changes are reviewed
before release publication/signing.

Each release tag gets an immutable policy record, so operators can keep multiple
release lines active at the same time and audit policy history later.

## Inputs

- `probe_run_id` (required): run ID of `kms_staging_probe_phala.yaml`
- `release_tag` (required): target policy tag (for example `1.2.3`)
- `probe_artifact_name` (optional): artifact name override
- `base_branch` (default `master`)
- `draft_pr` (default `true`)

## Outputs

The workflow updates:

- `policies/mero-kms-phala/<release_tag>.json`
- `policies/mero-kms-phala/index.json`

The `<release_tag>.json` file contains canonical `policy` values used by release
automation. The `index.json` file acts as the historical registry and includes:

- release tag -> policy file path mapping
- policy status
- policy SHA-256 digest

Then it opens/updates a PR with:

- source probe run URL
- artifact name
- copy/paste candidate `MERO_KMS_ALLOWED_*_JSON` values

If repository policy blocks PR creation from GitHub Actions, the workflow still
pushes the promotion branch and prints a manual compare URL in the job summary.

## Recommended flow

1. Run `kms_staging_probe_phala.yaml`
2. Review probe artifacts and summary
3. Run `kms_policy_promotion_pr.yaml` with the probe run ID
4. Review and merge PR
5. Merge version bump PR for same release tag
6. Release workflow reads `policies/mero-kms-phala/<tag>.json` automatically
