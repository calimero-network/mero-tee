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
- policy digest (`policy_sha256`)
- candidate values for reviewer inspection

If repository policy blocks PR creation from GitHub Actions, the workflow still
pushes the promotion branch and prints a manual compare URL in the job summary.

To enable automatic PR creation in restricted repositories, configure one of:

- `PR_CREATION_TOKEN` (recommended PAT secret), or
- `GH_TOKEN` (PAT secret)

with repository write access. The workflow falls back to `github.token` when
these secrets are not set.

## Recommended flow

### Automatic mode (recommended)

1. Merge version bump PR for target `mero-kms-phala` release tag.
2. `kms_policy_auto_pipeline.yaml` dispatches:
   - `kms_staging_probe_phala.yaml`
   - `kms_policy_promotion_pr.yaml`
3. Review and merge generated policy PR.
4. Release workflow runs on policy merge and publishes signed artifacts.

### Manual mode (fallback)

1. Merge version bump PR for same release tag.
2. Run `kms_staging_probe_phala.yaml`.
3. Review probe artifacts and summary.
4. Run `kms_policy_promotion_pr.yaml` with the probe run ID.
5. Review and merge policy PR.
6. Release workflow runs on policy merge and publishes signed artifacts.

## Notes

- Promotion PRs are the governance checkpoint.
- Release artifacts are generated from merged policy registry files, not from
  manual repository variable inputs.
