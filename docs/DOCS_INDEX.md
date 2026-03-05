# Documentation Source Index

This index maps documentation pages to their primary source files and related automation.

It is an index only. Update the actual documentation files listed below, not this file alone.

## Maintainer workflow

When changing release automation, policy workflows, or verification scripts:

1. Update the affected workflow/script.
2. Update the corresponding docs in this index.
3. Confirm README quick links remain accurate.
4. Refresh deep links in `docs/DOCS_NAVIGATION_MAP.md` if headings changed.

## Source mapping

| Document | Primary source | Related workflows/scripts | Audience |
|---|---|---|---|
| `docs/ARCHITECTURE.md` | Trust boundaries, enforcement points, and `core` vs `mero-tee` responsibilities | `crates/mero-kms-phala/src/handlers.rs`, `core/crates/merod/src/kms.rs`, release workflows | Operators, auditors |
| `docs/TRUST_AND_VERIFICATION.md` | Consolidated trust guarantees and verification entry point | `scripts/verify-kms-phala-release-assets.sh`, `scripts/verify-node-image-gcp-release-assets.sh`, `scripts/verify-release-assets.sh` | Operators, auditors |
| `docs/TEE_VERIFICATION_FOR_BEGINNERS.md` | Step-by-step verification guide for readers new to TEE and attestation | `scripts/verify-kms-phala-release-assets.sh`, `scripts/verify-node-image-gcp-release-assets.sh`, `scripts/verify-release-assets.sh` | Operators, auditors |
| `docs/platforms/README.md` | Platform lane navigation (`Phala KMS` vs `GCP node image`) | `docs/platforms/phala-kms.md`, `docs/platforms/gcp-merod.md` | Operators |
| `docs/platforms/phala-kms.md` | Phala KMS-plane deployment/operations runbook | `crates/mero-kms-phala/src/handlers.rs`, `scripts/apply-merod-kms-phala-attestation-config.sh` | Operators |
| `docs/platforms/gcp-merod.md` | GCP locked-image node-plane deployment/verification runbook | `packer/gcp/merod/*`, `release-node-image-gcp.yaml`, `scripts/verify-node-image-gcp-release-assets.sh` | Operators |
| `docs/REPO_RESTRUCTURE_PROPOSAL.md` | Proposed naming and repository-structure cleanup plan | workflows/scripts/policies/docs naming surface | Maintainers |
| `docs/verify-mrtd.md` | End-user/operator verification flow | `scripts/verify-node-image-gcp-release-assets.sh`, `scripts/verify_tdx_quote_ita.py` | Operators, auditors |
| `docs/MINIMAL_DOWNLOAD_SETS.md` | Minimal asset sets for quick verify vs full audit | `scripts/verify-kms-phala-release-assets.sh`, `scripts/verify-node-image-gcp-release-assets.sh`, `scripts/verify-release-assets.sh` | Operators, auditors |
| `docs/DOCS_NAVIGATION_MAP.md` | Maintainer deep-link and anchor map for docs | `README.md`, `docs/DOCS_INDEX.md` | Maintainers |
| `docs/kms-blue-green-rollout.md` | Decision-tree rollout and rollback procedure | `scripts/verify-kms-phala-release-assets.sh`, `scripts/generate-merod-kms-phala-attestation-config.sh` | Operators |
| `docs/kms-staging-probe-phala.md` | Staging probe process for KMS policy candidates | `kms-phala-staging-probe.yaml`, `scripts/extract_tdx_policy_candidates.py` | Release engineers |
| `docs/kms-policy-promotion-pr.md` | Manual PR promotion of KMS policy candidates | `kms-phala-policy-promotion-pr.yaml` | Release engineers |
| `docs/kms-policy-auto-pipeline.md` | Automatic KMS policy pipeline behavior | `kms-phala-policy-auto-pipeline.yaml` | Release engineers |
| `docs/locked-image-policy-promotion-pr.md` | Locked-image policy promotion flow | `node-image-gcp-policy-promotion-pr.yaml` | Release engineers |
| `docs/RELEASE_PIPELINE_SEQUENCE_DIAGRAMS.md` | Visual sequence diagrams for release workflows and auditing | `release-kms-phala.yaml`, `release-node-image-gcp.yaml`, `release-auditor.yaml` | Maintainers, release engineers |
| `docs/WORKFLOW_SETUP.md` | Required GitHub variables/secrets | All release/policy workflows | Maintainers |
| `scripts/check_release_version_sync.sh` | Validates KMS/merod version bump coupling and policy index consistency | `.github/workflows/release-version-sync-guard.yaml` | Maintainers |
| `docs/phala-kms-attestation-task-list.md` | KMS attestation implementation checklist | `crates/mero-kms-phala/*`, release scripts | Maintainers |
| `docs/phala-kms-key-protection-proposal.md` | Key protection direction/proposal | N/A (design doc) | Maintainers |
| `docs/phala-direct-kms-design.md` | Alternative architecture design | N/A (design doc) | Maintainers |
| `docs/MIGRATION_PLAN.md` | Historical migration plan | N/A (planning doc) | Maintainers |

## Release trust artifact references

| Artifact family | Source workflow | Primary verifier |
|---|---|---|
| KMS binaries + manifest/policy/signatures | `.github/workflows/release-kms-phala.yaml` | `scripts/verify-kms-phala-release-assets.sh` |
| Locked-image MRTD/provenance/signatures | `.github/workflows/release-node-image-gcp.yaml` | `scripts/verify-node-image-gcp-release-assets.sh` |

## Index update checklist

- [ ] Added/removed docs file reflected here.
- [ ] New workflow/script references linked here.
- [ ] README quick links updated if navigation changed.
