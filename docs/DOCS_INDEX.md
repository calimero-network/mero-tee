# Documentation Source Index

This index maps documentation pages to their primary source files and related automation.

It is an index only. Update the actual documentation files listed below, not this file alone.

## Maintainer workflow

When changing release automation, policy workflows, or verification scripts:

1. Update the affected workflow/script.
2. Update the corresponding docs in this index.
3. Confirm README quick links remain accurate.

## Source mapping

| Document | Primary source | Related workflows/scripts | Audience |
|---|---|---|---|
| `docs/ARCHITECTURE.md` | System trust model and component boundaries | `release-mero-kms-phala.yaml`, `gcp_locked_image_build.yaml` | Operators, auditors |
| `docs/deploy-phala.md` | Phala deployment runbook | `scripts/apply_merod_kms_attestation_config.sh` | Operators |
| `docs/deploy-gcp.md` | GCP locked-image deployment runbook | `packer/gcp/merod/*`, `gcp_locked_image_build.yaml` | Operators |
| `docs/verify-mrtd.md` | End-user/operator verification flow | `scripts/verify_locked_image_release_assets.sh`, `scripts/verify_tdx_quote_ita.py` | Operators, auditors |
| `docs/kms-blue-green-rollout.md` | Release-isolated rollout procedure | `scripts/verify_mero_kms_release_assets.sh`, `scripts/generate_merod_kms_attestation_config.sh` | Operators |
| `docs/kms-staging-probe-phala.md` | Staging probe process for KMS policy candidates | `kms_staging_probe_phala.yaml`, `scripts/extract_tdx_policy_candidates.py` | Release engineers |
| `docs/kms-policy-promotion-pr.md` | Manual PR promotion of KMS policy candidates | `kms_policy_promotion_pr.yaml` | Release engineers |
| `docs/kms-policy-auto-pipeline.md` | Automatic KMS policy pipeline behavior | `kms_policy_auto_pipeline.yaml` | Release engineers |
| `docs/locked-image-policy-promotion-pr.md` | Locked-image policy promotion flow | `locked_image_policy_promotion_pr.yaml` | Release engineers |
| `docs/RELEASE_PIPELINE_SEQUENCE_DIAGRAMS.md` | Visual sequence diagrams for release workflows and auditing | `release-mero-kms-phala.yaml`, `gcp_locked_image_build.yaml`, `release-auditor.yaml` | Maintainers, release engineers |
| `docs/WORKFLOW_SETUP.md` | Required GitHub variables/secrets | All release/policy workflows | Maintainers |
| `docs/phala-kms-attestation-task-list.md` | KMS attestation implementation checklist | `crates/mero-kms-phala/*`, release scripts | Maintainers |
| `docs/phala-kms-key-protection-proposal.md` | Key protection direction/proposal | N/A (design doc) | Maintainers |
| `docs/phala-direct-kms-design.md` | Alternative architecture design | N/A (design doc) | Maintainers |
| `docs/MIGRATION_PLAN.md` | Historical migration plan | N/A (planning doc) | Maintainers |

## Release trust artifact references

| Artifact family | Source workflow | Primary verifier |
|---|---|---|
| KMS binaries + manifest/policy/signatures | `.github/workflows/release-mero-kms-phala.yaml` | `scripts/verify_mero_kms_release_assets.sh` |
| Locked-image MRTD/provenance/signatures | `.github/workflows/gcp_locked_image_build.yaml` | `scripts/verify_locked_image_release_assets.sh` |

## Index update checklist

- [ ] Added/removed docs file reflected here.
- [ ] New workflow/script references linked here.
- [ ] README quick links updated if navigation changed.
