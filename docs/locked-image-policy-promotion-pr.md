# Locked-image policy promotion workflow (PR)

Workflow file:

- `.github/workflows/locked_image_policy_promotion_pr.yaml`

## Purpose

Promote versioned locked-image measurement policy records into this repository so
image trust policy history is reviewed and auditable in git.

This workflow is auto-dispatched by `gcp_locked_image_build.yaml` after release
asset publication, and can also be run manually for backfills.

## Inputs

- `release_tag` (required): target release tag (for example `2.1.4`)
- `base_branch` (default `master`)
- `draft_pr` (default `true`)

## What it does

1. Downloads release assets for the provided tag.
2. Prefers `merod-locked-image-policy.json` when available.
3. Falls back to synthesizing policy from `published-mrtds.json` (RTMR arrays
   empty) for older releases.
4. Updates:
   - `policies/merod-locked-image/<tag>.json`
   - `policies/merod-locked-image/index.json`
5. Opens (or attempts to open) a PR.

If PR creation is blocked for the workflow token, the branch is still pushed and
the workflow summary prints a manual compare URL.
