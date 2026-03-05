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
| `docs/architecture/trust-boundaries.md` | Trust boundaries, enforcement points, and `core` vs `mero-tee` responsibilities | `src/handlers.rs`, `core/crates/merod/src/kms.rs`, release workflows | Operators, auditors |
| `docs/release/trust-and-verification.md` | Consolidated trust guarantees and verification entry point | `scripts/release/verify-kms-phala-release-assets.sh`, `scripts/release/verify-node-image-gcp-release-assets.sh`, `scripts/release/verify-release-assets.sh` | Operators, auditors |
| `docs/release/verification-beginner.md` | Step-by-step verification guide for readers new to TEE and attestation | `scripts/release/verify-kms-phala-release-assets.sh`, `scripts/release/verify-node-image-gcp-release-assets.sh`, `scripts/release/verify-release-assets.sh` | Operators, auditors |
| `docs/runbooks/platforms/README.md` | Platform lane navigation (`Phala KMS` vs `GCP node image`) | `docs/runbooks/platforms/phala-kms.md`, `docs/runbooks/platforms/gcp-merod.md` | Operators |
| `docs/runbooks/platforms/phala-kms.md` | Phala KMS-plane deployment/operations runbook | `src/handlers.rs`, `scripts/policy/apply-merod-kms-phala-attestation-config.sh` | Operators |
| `docs/runbooks/platforms/gcp-merod.md` | GCP node-image-gcp deployment/verification runbook | `node-image-gcp/*`, `release-node-image-gcp.yaml`, `scripts/release/verify-node-image-gcp-release-assets.sh` | Operators |
| `docs/REPO_RESTRUCTURE_PROPOSAL.md` | Proposed naming and repository-structure cleanup plan | workflows/scripts/policies/docs naming surface | Maintainers |
| `docs/runbooks/operations/verify-mrtd.md` | End-user/operator verification flow | `scripts/release/verify-node-image-gcp-release-assets.sh`, `scripts/attestation/verify_tdx_quote_ita.py` | Operators, auditors |
| `docs/release/minimal-download-sets.md` | Minimal asset sets for quick verify vs full audit | `scripts/release/verify-kms-phala-release-assets.sh`, `scripts/release/verify-node-image-gcp-release-assets.sh`, `scripts/release/verify-release-assets.sh` | Operators, auditors |
| `docs/DOCS_NAVIGATION_MAP.md` | Maintainer deep-link and anchor map for docs | `README.md`, `docs/DOCS_INDEX.md` | Maintainers |
| `docs/runbooks/operations/kms-blue-green-rollout.md` | Decision-tree rollout and rollback procedure | `scripts/release/verify-kms-phala-release-assets.sh`, `scripts/policy/generate-merod-kms-phala-attestation-config.sh` | Operators |
| `docs/policies/kms-phala-staging-probe.md` | Staging probe process for KMS policy candidates | `kms-phala-staging-probe.yaml`, `scripts/attestation/extract_tdx_policy_candidates.py` | Release engineers |
| `docs/policies/kms-phala-policy-promotion.md` | Manual PR promotion of KMS policy candidates | `kms-phala-policy-promotion-pr.yaml` | Release engineers |
| `docs/policies/kms-phala-policy-auto-pipeline.md` | Automatic KMS policy pipeline behavior | `kms-phala-policy-auto-pipeline.yaml` | Release engineers |
| `docs/policies/node-image-gcp-policy-promotion.md` | node-image-gcp policy promotion flow | `node-image-gcp-policy-promotion-pr.yaml` | Release engineers |
| `docs/release/pipeline-sequence-diagrams.md` | Visual sequence diagrams for release workflows and auditing | `release-kms-phala.yaml`, `release-node-image-gcp.yaml`, `release-auditor.yaml` | Maintainers, release engineers |
| `docs/release/workflow-setup.md` | Required GitHub variables/secrets | All release/policy workflows | Maintainers |
| `scripts/policy/check_release_version_sync.sh` | Validates KMS/merod version bump coupling and policy index consistency | `.github/workflows/release-version-sync-guard.yaml` | Maintainers |
| `docs/policies/kms-phala-attestation-task-list.md` | KMS attestation implementation checklist | `src/*`, release scripts | Maintainers |
| `docs/architecture/phala-kms-key-protection-proposal.md` | Key protection direction/proposal | N/A (design doc) | Maintainers |
| `docs/architecture/phala-direct-kms-design.md` | Alternative architecture design | N/A (design doc) | Maintainers |
| `docs/architecture/migration-plan.md` | Historical migration plan | N/A (planning doc) | Maintainers |

## Release trust artifact references

| Artifact family | Source workflow | Primary verifier |
|---|---|---|
| KMS binaries + manifest/policy/signatures | `.github/workflows/release-kms-phala.yaml` | `scripts/release/verify-kms-phala-release-assets.sh` |
| node-image-gcp MRTD/provenance/signatures | `.github/workflows/release-node-image-gcp.yaml` | `scripts/release/verify-node-image-gcp-release-assets.sh` |

## Index update checklist

- [ ] Added/removed docs file reflected here.
- [ ] New workflow/script references linked here.
- [ ] README quick links updated if navigation changed.
