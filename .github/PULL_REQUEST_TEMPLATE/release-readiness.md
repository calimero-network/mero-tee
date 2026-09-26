---
name: Release readiness checklist
about: Use this template for release and release-adjacent PRs.
title: "[release] "
labels: release
assignees: ""
---

## Release scope

- Release family:
  - [ ] mero-kms (`release-kms`, GCP TDX images)
  - [ ] node-image-gcp (`release-node-image-gcp`)
  - [ ] both
- Target version/tag: `<X.Y.Z>`

## Pre-merge checklist

- [ ] Version bump (mero-kms/Cargo.toml and versions.json) are aligned for this release tag.
- [ ] Workflow changes (if any) were reviewed by code owners.
- [ ] Release helper scripts still pass shell syntax checks:
  - [ ] `scripts/release/verify-kms-release-assets.sh`
  - [ ] `scripts/release/verify-node-image-gcp-release-assets.sh`
- [ ] Operator-facing docs were updated for behavior changes.
- [ ] Deployment snippets pin release images by name (`merotee-kms-<profile>-<version>`), not by family.

## Verification plan

- [ ] `scripts/release/verify-kms-release-assets.sh <X.Y.Z>` succeeds (if KMS assets are expected).
- [ ] `scripts/release/verify-node-image-gcp-release-assets.sh <X.Y.Z>` succeeds (if node-image-gcp assets are expected).
- [ ] Sigstore identity expectations were checked against workflow identity:
  - [ ] KMS workflow identity regex
  - [ ] node-image-gcp workflow identity regex

## Risk and rollback

- [ ] Rollout plan (blue/green or staged) is documented.
- [ ] Rollback path is documented and tested.
- [ ] Compatibility impact to existing nodes/operators is documented.

## Post-release follow-up

- [ ] Release notes include verification command snippets.
- [ ] KMS draft release reviewed and published by human.
- [ ] Links to published release assets are recorded in PR comments.
