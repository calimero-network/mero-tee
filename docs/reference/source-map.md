# Documentation Source Map (Canonical)

This is the canonical maintainer map for documentation ownership and deep links.

Use this file as the source of truth for:

- doc-to-code/workflow mapping
- high-traffic anchor links for PRs and release notes

## Maintainer workflow

When changing release automation, policy workflows, or verification scripts:

1. Update the affected workflow/script.
2. Update the corresponding docs.
3. Update this source map if ownership/anchors changed.
4. Confirm entry links in `docs/README.md` and `README.md`.

## Source mapping

| Document | Primary source | Related workflows/scripts | Audience |
|---|---|---|---|
| `docs/README.md` | Canonical docs portal and audience routes | `README.md`, all major docs entry points | Operators, release engineers, auditors, maintainers |
| `docs/getting-started/README.md` | First-run lane selection and onboarding checklist | Platform runbooks, trust verification docs | Operators |
| `docs/architecture/trust-boundaries.md` | Trust boundaries and enforcement points | `mero-kms/src/handlers/*`, `core/crates/merod/src/kms.rs`, release workflows | Operators, auditors |
| `docs/DOCS_GRAPH.md` | System context and attestation sequence diagrams | `docs/diagrams/src/*.mmd` | Operators, maintainers |
| `docs/runbooks/platforms/phala-kms.md` | Phala KMS-plane deployment/operations | `mero-kms/src/main.rs`, `scripts/policy/apply-merod-kms-phala-attestation-config.sh` | Operators |
| `docs/runbooks/platforms/gcp-merod.md` | GCP node-image-gcp deployment/verification | `mero-tee/*`, `release-node-image-gcp.yaml`, `scripts/release/verify-node-image-gcp-release-assets.sh` | Operators |
| `docs/runbooks/operations/kms-blue-green-rollout.md` | KMS rollout and rollback decision tree | `scripts/release/verify-kms-phala-release-assets.sh`, policy scripts | Operators |
| `docs/release/trust-and-verification.md` | Canonical trust/verification guide | `scripts/release/verify-*.sh`, policy scripts | Operators, auditors |
| `docs/release/pipeline-sequence-diagrams.md` | Release/audit sequence diagrams | `.github/workflows/release-*.yaml`, `release-auditor.yaml` | Maintainers, release engineers |
| `docs/policies/*.md` | Policy promotion and staging procedures | policy workflows + `scripts/policy/*.sh` | Release engineers |
| `docs/diagrams/README.md` | Diagram catalog and coverage matrix | `docs/diagrams/src/*.mmd` | Maintainers, operators |
| `docs/projects/README.md` | Repo/folder responsibility boundaries | top-level project READMEs | Maintainers, operators |
| `docs/GLOSSARY.md` | Canonical terminology and naming rules | all docs/workflows/scripts | Maintainers, operators |
| `docs/adr/README.md` + `docs/adr/*.md` | Accepted architecture/security/process decisions | `mero-kms/src/config.rs`, release workflows | Maintainers, auditors |

## High-traffic deep links

| Page | Key anchors |
|---|---|
| [`README.md`](../../README.md) | [`#documentation`](../../README.md#documentation), [`#releases`](../../README.md#releases) |
| [`docs/README.md`](../README.md) | [`#start-paths-by-audience`](../README.md#start-paths-by-audience), [`#documentation-map`](../README.md#documentation-map) |
| [`docs/DOCS_GRAPH.md`](../DOCS_GRAPH.md) | [`#system-overview`](../DOCS_GRAPH.md#system-overview), [`#attestation-flow-phala-kms-lane`](../DOCS_GRAPH.md#attestation-flow-phala-kms-lane) |
| [`docs/release/trust-and-verification.md`](../release/trust-and-verification.md) | [`#operator-quick-path-release-acceptance`](../release/trust-and-verification.md#operator-quick-path-release-acceptance), [`#runtime-node-measurement-verification-mrtdrtmr`](../release/trust-and-verification.md#runtime-node-measurement-verification-mrtdrtmr) |
| [`docs/runbooks/operations/kms-blue-green-rollout.md`](../runbooks/operations/kms-blue-green-rollout.md) | [`#decision-tree`](../runbooks/operations/kms-blue-green-rollout.md#decision-tree), [`#rollback-branches`](../runbooks/operations/kms-blue-green-rollout.md#rollback-branches) |

## Update checklist

- [ ] Added/removed docs reflected in this map
- [ ] Updated anchors still resolve after header changes
- [ ] Entry links in `docs/README.md` and root `README.md` still valid
