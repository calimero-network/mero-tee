# Docs Navigation & Anchor Map

This file is a maintainer-oriented shortcut map for high-traffic documentation pages and their key anchors.

Use these links in PR descriptions, release notes, and issue comments to avoid ambiguous pointers like “see architecture doc”.

## Core entry points

| Page | Purpose | Key anchors |
|---|---|---|
| [README.md](../README.md) | Operator-facing repository entry point | [`#quick-links`](../README.md#quick-links), [`#releases`](../README.md#releases), [`#what-signatures-prove-and-do-not-prove`](../README.md#what-signatures-prove-and-do-not-prove) |
| [docs/DOCS_INDEX.md](DOCS_INDEX.md) | Source-of-truth mapping between docs and automation | [`#source-mapping`](DOCS_INDEX.md#source-mapping), [`#release-trust-artifact-references`](DOCS_INDEX.md#release-trust-artifact-references) |
| [docs/DOCS_GRAPH.md](DOCS_GRAPH.md) | Architecture diagram: KMS, mero-tee, nodes, attestation | [`#system-overview`](DOCS_GRAPH.md#system-overview), [`#attestation-flow-phala-kms-lane`](DOCS_GRAPH.md#attestation-flow-phala-kms-lane) |
| [docs/architecture/trust-boundaries.md](architecture/trust-boundaries.md) | Trust boundaries and attestation enforcement points | [`#repository-boundaries`](architecture/trust-boundaries.md#repository-boundaries), [`#platform-lanes-not-symmetric-deployments`](architecture/trust-boundaries.md#platform-lanes-not-symmetric-deployments), [`#attestation-enforcement-points`](architecture/trust-boundaries.md#attestation-enforcement-points) |
| [docs/runbooks/platforms/README.md](runbooks/platforms/README.md) | Platform-specific navigation entrypoint | [`#runbooks`](runbooks/platforms/README.md#runbooks) |
| [docs/REPO_RESTRUCTURE_PROPOSAL.md](REPO_RESTRUCTURE_PROPOSAL.md) | Naming and structure cleanup proposal | [`#3-proposed-rename-map-servicesassetsworkflowsscripts`](REPO_RESTRUCTURE_PROPOSAL.md#3-proposed-rename-map-servicesassetsworkflowsscripts), [`#4-proposed-repository-structure`](REPO_RESTRUCTURE_PROPOSAL.md#4-proposed-repository-structure), [`#5-execution-plan-breaking-changes-allowed`](REPO_RESTRUCTURE_PROPOSAL.md#5-execution-plan-breaking-changes-allowed) |

## Verification and release docs

| Page | When to link it | Key anchors |
|---|---|---|
| [docs/release/trust-and-verification.md](release/trust-and-verification.md) | Canonical onboarding + trust + runtime measurement verification | [`#operator-quick-path-release-acceptance`](release/trust-and-verification.md#operator-quick-path-release-acceptance), [`#verification-direction-matrix-who-verifies-whom`](release/trust-and-verification.md#verification-direction-matrix-who-verifies-whom), [`#runtime-node-measurement-verification-mrtdrtmr`](release/trust-and-verification.md#runtime-node-measurement-verification-mrtdrtmr), [`#why-some-rtmrs-may-match-across-different-image-profiles`](release/trust-and-verification.md#why-some-rtmrs-may-match-across-different-image-profiles) |
| [docs/release/verification-examples.md](release/verification-examples.md) | Explaining expected verifier output or debugging failures | [`#kms-release-asset-verification`](release/verification-examples.md#kms-release-asset-verification), [`#node-image-gcp-release-asset-verification`](release/verification-examples.md#node-image-gcp-release-asset-verification), [`#operator-troubleshooting-checklist`](release/verification-examples.md#operator-troubleshooting-checklist) |
| [docs/release/workflow-setup.md](release/workflow-setup.md) | Release workflow setup, secrets/vars, CI dependencies | [`#required-github-repo-variables`](release/workflow-setup.md#required-github-repo-variables), [`#required-github-secrets`](release/workflow-setup.md#required-github-secrets), [`#release-sbom-assets`](release/workflow-setup.md#release-sbom-assets) |
| [docs/release/taxonomy.md](release/taxonomy.md) | Stable/RC/hotfix release class expectations | [`#release-classes`](release/taxonomy.md#release-classes), [`#release-note-minimum-content`](release/taxonomy.md#release-note-minimum-content) |

## Operational runbooks

| Page | Operational phase | Key anchors |
|---|---|---|
| [docs/runbooks/operations/kms-blue-green-rollout.md](runbooks/operations/kms-blue-green-rollout.md) | KMS rollout and rollback operations | [`#bluegreen-deployment-steps`](runbooks/operations/kms-blue-green-rollout.md#bluegreen-deployment-steps), [`#rollback`](runbooks/operations/kms-blue-green-rollout.md#rollback), [`#guardrails`](runbooks/operations/kms-blue-green-rollout.md#guardrails) |
| [docs/runbooks/platforms/phala-kms.md](runbooks/platforms/phala-kms.md) | Phala KMS-plane deployment and operations | [`#1-scope-and-responsibility`](runbooks/platforms/phala-kms.md#1-scope-and-responsibility), [`#5-configure-merod-with-release-pinned-attestation-policy`](runbooks/platforms/phala-kms.md#5-configure-merod-with-release-pinned-attestation-policy), [`#7-common-mistakes-to-avoid`](runbooks/platforms/phala-kms.md#7-common-mistakes-to-avoid) |
| [docs/runbooks/platforms/gcp-merod.md](runbooks/platforms/gcp-merod.md) | GCP node-plane node-image-gcp deployment and verification | [`#3-verify-node-image-gcp-release-assets-first`](runbooks/platforms/gcp-merod.md#3-verify-node-image-gcp-release-assets-first), [`#5-verify-runtime-measurements-after-boot`](runbooks/platforms/gcp-merod.md#5-verify-runtime-measurements-after-boot), [`#7-common-mistakes-to-avoid`](runbooks/platforms/gcp-merod.md#7-common-mistakes-to-avoid) |

## Maintainer update checklist

- [ ] New doc added? Add it here with at least one anchor.
- [ ] Header renamed in an existing doc? Update anchor links here.
- [ ] README quick links changed? Ensure this map still points at canonical entry sections.
