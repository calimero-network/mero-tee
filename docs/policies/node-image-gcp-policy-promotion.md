# node-image-gcp policy promotion workflow (PR)

Workflow file:

- `.github/workflows/node-image-gcp-policy-promotion-pr.yaml`

## Purpose

Promote versioned node-image-gcp measurement policy records into this repository so
image trust policy history is reviewed and auditable in git.

This workflow is auto-dispatched by `release-node-image-gcp.yaml` after release
asset publication, and can also be run manually for backfills.

## Inputs

- `release_tag` (required): target release tag (for example `2.1.4`)
- `base_branch` (default `master`)
- `draft_pr` (default `true`)

## What it does

1. Downloads release assets for the provided tag.
2. Prefers `node-image-gcp-policy.json` when available.
3. Falls back to synthesizing policy from `published-mrtds.json` (RTMR arrays
   empty) for older releases.
4. Updates:
   - `policies/mero-tee/<tag>.json`
   - `policies/index.json`
5. Opens (or attempts to open) a PR.

If PR creation is blocked for the workflow token, the branch is still pushed and
the workflow summary prints a manual compare URL.
