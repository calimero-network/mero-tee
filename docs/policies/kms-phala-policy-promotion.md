# KMS policy promotion process (PR-based governance)

This workflow promotes a previously collected staging probe artifact into a
reviewable pull request that updates versioned policy files in this repository.

Canonical automation/components:

- `.github/workflows/kms-phala-staging-probe.yaml`
- `scripts/policy/generate-merod-kms-phala-attestation-config.sh`
- `scripts/policy/apply-merod-kms-phala-attestation-config.sh`
- `scripts/policy/check_release_version_sync.sh`

## Purpose

`kms-phala-staging-probe.yaml` collects **candidate** values from a staged CVM.
Policy changes are promoted through normal PR review in this repository (policy
files + index updates), then consumed by release automation.

Each release tag gets an immutable policy record, so operators can keep multiple
release lines active at the same time and audit policy history later.

## Promotion outputs

The workflow updates:

- `policies/kms-phala/<release_tag>.json`
- `policies/index.json`

The `<release_tag>.json` file contains canonical `policy` values used by release
automation. The shared `policies/index.json` file acts as the historical registry and includes:

- release version -> KMS/merod tag mapping
- KMS and merod policy file paths
- policy SHA-256 digests

Promotion PRs should include:

- source probe run URL
- artifact name
- policy digest (`policy_sha256`)
- candidate values for reviewer inspection

Automation can prepare artifacts and candidate payloads; PR creation/merge
remains repository-governed.

## Recommended flow

### Automatic mode (recommended)

1. Merge version bump PR for target `mero-kms-phala` release tag.
2. Run `kms-phala-staging-probe.yaml` (or an equivalent staged probe run).
3. Promote candidate values into `policies/kms-phala/<release_tag>.json` and
   `policies/index.json` via PR.
4. Review and merge policy PR.
5. Release workflow publishes signed artifacts from merged policy inputs.

### Manual mode (fallback)

1. Merge version bump PR for same release tag.
2. Run `kms-phala-staging-probe.yaml`.
3. Review probe artifacts and summary.
4. Update `policies/kms-phala/<tag>.json` and `policies/index.json` in a PR.
5. Review and merge policy PR.
6. Release workflow runs on policy merge and publishes signed artifacts.

## Notes

- Promotion PRs are the governance checkpoint.
- Release artifacts are generated from merged policy registry files, not from
  manual repository variable inputs.
