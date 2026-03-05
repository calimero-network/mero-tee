# Docs Navigation & Anchor Map

This file is a maintainer-oriented shortcut map for high-traffic documentation pages and their key anchors.

Use these links in PR descriptions, release notes, and issue comments to avoid ambiguous pointers like “see architecture doc”.

## Core entry points

| Page | Purpose | Key anchors |
|---|---|---|
| [README.md](../README.md) | Operator-facing repository entry point | [`#quick-links`](../README.md#quick-links), [`#releases`](../README.md#releases), [`#what-signatures-prove-and-do-not-prove`](../README.md#what-signatures-prove-and-do-not-prove) |
| [docs/DOCS_INDEX.md](DOCS_INDEX.md) | Source-of-truth mapping between docs and automation | [`#source-mapping`](DOCS_INDEX.md#source-mapping), [`#release-trust-artifact-references`](DOCS_INDEX.md#release-trust-artifact-references) |
| [docs/ARCHITECTURE.md](ARCHITECTURE.md) | Trust model and verification concepts | [`#trust-model`](ARCHITECTURE.md#trust-model), [`#verification`](ARCHITECTURE.md#verification) |

## Verification and release docs

| Page | When to link it | Key anchors |
|---|---|---|
| [docs/TEE_VERIFICATION_FOR_BEGINNERS.md](TEE_VERIFICATION_FOR_BEGINNERS.md) | First-time operator/auditor onboarding with plain-language verification flow | [`#4-recommended-verification-flow`](TEE_VERIFICATION_FOR_BEGINNERS.md#4-recommended-verification-flow), [`#5-what-success-means-and-does-not-mean`](TEE_VERIFICATION_FOR_BEGINNERS.md#5-what-success-means-and-does-not-mean), [`#6-common-failures-and-interpretation`](TEE_VERIFICATION_FOR_BEGINNERS.md#6-common-failures-and-interpretation) |
| [docs/verify-mrtd.md](verify-mrtd.md) | Verifying deployed node measurements against published MRTDs | [`#verify-signed-release-assets-first-sigstore-keyless`](verify-mrtd.md#verify-signed-release-assets-first-sigstore-keyless), [`#quick-verification-mrtd-comparison`](verify-mrtd.md#quick-verification-mrtd-comparison), [`#what-signatures-prove-and-do-not-prove`](verify-mrtd.md#what-signatures-prove-and-do-not-prove) |
| [docs/release-verification-examples.md](release-verification-examples.md) | Explaining expected verifier output or debugging failures | [`#kms-release-asset-verification`](release-verification-examples.md#kms-release-asset-verification), [`#locked-image-release-asset-verification`](release-verification-examples.md#locked-image-release-asset-verification), [`#operator-troubleshooting-checklist`](release-verification-examples.md#operator-troubleshooting-checklist) |
| [docs/WORKFLOW_SETUP.md](WORKFLOW_SETUP.md) | Release workflow setup, secrets/vars, CI dependencies | [`#required-github-repo-variables`](WORKFLOW_SETUP.md#required-github-repo-variables), [`#required-github-secrets`](WORKFLOW_SETUP.md#required-github-secrets), [`#release-sbom-assets`](WORKFLOW_SETUP.md#release-sbom-assets) |
| [docs/RELEASE_TAXONOMY.md](RELEASE_TAXONOMY.md) | Stable/RC/hotfix release class expectations | [`#release-classes`](RELEASE_TAXONOMY.md#release-classes), [`#release-note-minimum-content`](RELEASE_TAXONOMY.md#release-note-minimum-content) |

## Operational runbooks

| Page | Operational phase | Key anchors |
|---|---|---|
| [docs/kms-blue-green-rollout.md](kms-blue-green-rollout.md) | KMS rollout and rollback operations | [`#bluegreen-deployment-steps`](kms-blue-green-rollout.md#bluegreen-deployment-steps), [`#rollback`](kms-blue-green-rollout.md#rollback), [`#guardrails`](kms-blue-green-rollout.md#guardrails) |
| [docs/deploy-phala.md](deploy-phala.md) | Deploying merod with KMS attestation on Phala | [`#setting-up-merod-for-tee`](deploy-phala.md#setting-up-merod-for-tee), [`#production-pinning-mrtdrtmr`](deploy-phala.md#production-pinning-mrtdrtmr) |
| [docs/deploy-gcp.md](deploy-gcp.md) | Deploying locked-image flow on GCP | [`#deployment-options`](deploy-gcp.md#deployment-options), [`#verification`](deploy-gcp.md#verification) |

## Maintainer update checklist

- [ ] New doc added? Add it here with at least one anchor.
- [ ] Header renamed in an existing doc? Update anchor links here.
- [ ] README quick links changed? Ensure this map still points at canonical entry sections.
