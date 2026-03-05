---
name: Release readiness checklist
about: Use this template for release and release-adjacent PRs.
title: "[release] "
labels: release
assignees: ""
---

## Release scope

- Release family:
  - [ ] `mero-kms-phala`
  - [ ] locked-image (`gcp_locked_image_build`)
  - [ ] both
- Target version/tag: `<X.Y.Z>`
- Related policy entry:
  - [ ] `policies/index.json` includes target mapping
  - [ ] mapped policy file exists and is reviewed

## Pre-merge checklist

- [ ] Version bump and policy mapping are aligned for this release tag.
- [ ] Workflow changes (if any) were reviewed by code owners.
- [ ] Release helper scripts still pass shell syntax checks:
  - [ ] `scripts/verify-kms-phala-release-assets.sh`
  - [ ] `scripts/verify-node-image-gcp-release-assets.sh`
- [ ] Operator-facing docs were updated for behavior changes.
- [ ] Deployment snippets use pinned tag/digest references (no mutable `:latest`).

## Verification plan

- [ ] `scripts/verify-kms-phala-release-assets.sh <X.Y.Z>` succeeds (if KMS assets are expected).
- [ ] `scripts/verify-node-image-gcp-release-assets.sh <X.Y.Z>` succeeds (if locked-image assets are expected).
- [ ] Sigstore identity expectations were checked against workflow identity:
  - [ ] KMS workflow identity regex
  - [ ] locked-image workflow identity regex

## Risk and rollback

- [ ] Rollout plan (blue/green or staged) is documented.
- [ ] Rollback path is documented and tested.
- [ ] Compatibility impact to existing nodes/operators is documented.

## Post-release follow-up

- [ ] Release notes include verification command snippets.
- [ ] Any required policy-promotion workflow has been dispatched/verified.
- [ ] Links to published release assets are recorded in PR comments.
