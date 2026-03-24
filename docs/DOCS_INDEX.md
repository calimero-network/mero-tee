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
| `docs/architecture/trust-boundaries.md` | Trust boundaries, enforcement points, and `core` vs `mero-tee` responsibilities | `mero-kms/src/handlers/get_key.rs`, `mero-kms/src/handlers/attest.rs`, `core/crates/merod/src/kms.rs`, release workflows | Operators, auditors |
| `docs/release/trust-and-verification.md` | Canonical trust/verification/measurement guide (operator + client) | `scripts/release/verify-kms-phala-release-assets.sh`, `scripts/release/verify-node-image-gcp-release-assets.sh`, `scripts/release/verify-release-assets.sh`, profile policy scripts | Operators, auditors |
| `docs/release/rtmr3-image-legitimacy-verification.md` | RTMR3 extension formula, generation flow, and client verification design | `calimero-init.sh.j2`, `assemble-published-mrtd-payload.sh`, `mero-kms/src/handlers/get_key.rs`, `core/crates/merod/src/kms_policy.rs` | Operators, auditors, maintainers |
| `docs/runbooks/platforms/README.md` | Platform lane navigation (`Phala KMS` vs `GCP node image`) | `docs/runbooks/platforms/phala-kms.md`, `docs/runbooks/platforms/gcp-merod.md` | Operators |
| `docs/runbooks/platforms/phala-kms.md` | Phala KMS-plane deployment/operations runbook | `mero-kms/src/main.rs`, `mero-kms/src/handlers/get_key.rs`, `scripts/policy/apply-merod-kms-phala-attestation-config.sh` | Operators |
| `docs/runbooks/platforms/gcp-merod.md` | GCP node-image-gcp deployment/verification runbook | `mero-tee/*`, `release-node-image-gcp.yaml`, `scripts/release/verify-node-image-gcp-release-assets.sh` | Operators |
| `docs/REPO_RESTRUCTURE_PROPOSAL.md` | Proposed naming and repository-structure cleanup plan | workflows/scripts/policies/docs naming surface | Maintainers |
| `docs/release/minimal-download-sets.md` | Minimal asset sets for quick verify vs full audit | `scripts/release/verify-kms-phala-release-assets.sh`, `scripts/release/verify-node-image-gcp-release-assets.sh`, `scripts/release/verify-release-assets.sh` | Operators, auditors |
| `docs/README.md` | Canonical documentation portal and audience-based navigation | `README.md`, all major docs entry points | Operators, release engineers, auditors, maintainers |
| `docs/DOCS_NAVIGATION_MAP.md` | Maintainer deep-link and anchor map for docs | `README.md`, `docs/DOCS_INDEX.md` | Maintainers |
| `docs/diagrams/README.md` | Central index for UML/flow/sequence diagrams | `docs/DOCS_GRAPH.md`, `docs/release/pipeline-sequence-diagrams.md`, runbooks | Maintainers, operators |
| `docs/DOCS_GRAPH.md` | Architecture diagram: KMS, mero-tee, regular nodes, attestation flow | `README.md`, `docs/architecture/trust-boundaries.md` | Operators, maintainers |
| `docs/runbooks/operations/kms-blue-green-rollout.md` | Decision-tree rollout and rollback procedure | `scripts/release/verify-kms-phala-release-assets.sh`, `scripts/policy/generate-merod-kms-phala-attestation-config.sh` | Operators |
| `docs/policies/kms-phala-staging-probe.md` | Staging probe process for KMS policy candidates | `kms-phala-staging-probe.yaml`, `scripts/attestation/shared/extract_tdx_policy_candidates.py` | Release engineers |
| `docs/policies/kms-phala-policy-promotion.md` | Manual promotion of KMS policy candidates | `kms-phala-staging-probe.yaml`, `scripts/policy/generate-merod-kms-phala-attestation-config.sh`, `scripts/policy/apply-merod-kms-phala-attestation-config.sh` | Release engineers |
| `docs/policies/kms-phala-policy-auto-pipeline.md` | KMS policy pipeline design and operating model | `kms-phala-staging-probe.yaml`, `scripts/attestation/shared/extract_tdx_policy_candidates.py`, `scripts/policy/*.sh` | Release engineers |
| `docs/policies/node-image-gcp-policy-promotion.md` | node-image-gcp policy promotion flow | `release-node-image-gcp.yaml`, `scripts/release/node-image-gcp/assemble-published-mrtd-payload.sh`, `scripts/release/verify-node-image-gcp-release-assets.sh` | Release engineers |
| `docs/release/pipeline-sequence-diagrams.md` | Visual sequence diagrams for release workflows and auditing | `release-kms-phala.yaml`, `release-node-image-gcp.yaml`, `release-auditor.yaml` | Maintainers, release engineers |
| `docs/release/workflow-setup.md` | Required GitHub variables/secrets | All release/policy workflows | Maintainers |
| `docs/GLOSSARY.md` | Canonical terminology for lanes, profiles, release terms, and attestation vocabulary | All docs/workflows/scripts (naming consistency) | Maintainers, operators |
| `docs/adr/README.md` + `docs/adr/*.md` | Accepted architecture/security/process decisions | `mero-kms/src/config.rs`, release workflows, `scripts/policy/check_release_version_sync.sh` | Maintainers, auditors |
| `scripts/policy/check_release_version_sync.sh` | Validates KMS/merod version bump coupling and policy index consistency | `.github/workflows/release-version-sync-guard.yaml` | Maintainers |
| `docs/policies/kms-phala-attestation-task-list.md` | KMS attestation implementation checklist | `mero-kms/src/*`, release scripts | Maintainers |
| `docs/architecture/phala-kms-key-protection-proposal.md` | Key protection direction/proposal | N/A (design doc) | Maintainers |
| `docs/architecture/phala-direct-kms-design.md` | Alternative architecture design | N/A (design doc) | Maintainers |
| `docs/architecture/migration-plan.md` | Historical migration plan | N/A (planning doc) | Maintainers |

## Release trust artifact references

| Artifact family | Source workflow | Primary verifier |
|---|---|---|
| KMS binaries + manifest/policy/signatures | `.github/workflows/release-kms-phala.yaml` | `scripts/release/verify-kms-phala-release-assets.sh` |
| node-image-gcp MRTD/provenance/signatures | `.github/workflows/release-node-image-gcp.yaml` | `scripts/release/verify-node-image-gcp-release-assets.sh` |

## Release script module layout

- KMS release helpers: `scripts/release/kms-phala/*.sh`
- Node-image release helpers: `scripts/release/node-image-gcp/*.sh`
- Release-level verifiers and E2E checks: `scripts/release/verify-*.sh`, `scripts/release/e2e-*.sh` (including `e2e-mero-tee-node-post-release.sh` and workflow `post-release-mero-tee-node-e2e.yaml`)

## Index update checklist

- [ ] Added/removed docs file reflected here.
- [ ] New workflow/script references linked here.
- [ ] README quick links updated if navigation changed.
