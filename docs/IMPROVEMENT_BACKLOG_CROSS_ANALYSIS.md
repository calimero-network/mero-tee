# Improvement Backlog (Cross-Analysis vs near-outlayer)

Date: 2026-03-05  
Scope: `calimero-network/mero-tee`  
Reference analyzed: `fastnear/near-outlayer`

This backlog turns the cross-analysis into an implementation-ready plan.

## Prioritization model

- **P0**: High security/trust or release reliability impact; do first.
- **P1**: Important improvements for operator UX, maintenance, and auditability.
- **P2**: Nice-to-have improvements and polish.

Effort estimate:

- **S**: 0.5-1 day
- **M**: 2-4 days
- **L**: 1+ week

---

## Backlog items (30)

| ID | Priority | Effort | Workstream | Item | Acceptance criteria |
|---|---|---|---|---|---|
| BL-001 | P0 | S | Release UX | Add structured GitHub release body template for KMS + locked-image releases | Each release includes artifact table, hashes/digests, one-command verify snippets |
| BL-002 | P1 | M | Release UX | Auto-generate release notes body from workflow outputs | Workflow fills version, commit, policy path, run URL, and verification links |
| BL-003 | P0 | M | Supply chain | Enable OCI provenance attestations for published container images | Container jobs emit attestations verifiable with `gh attestation verify` |
| BL-004 | P0 | M | Supply chain | Enable SBOM generation and publish signed SBOM artifacts | Release includes SBOM files with Sigstore signatures and verification docs |
| BL-005 | P1 | M | Supply chain | Add Rekor transparency references into release manifests | Manifest includes Rekor UUID/log index per signed asset |
| BL-006 | P0 | M | Verification automation | Add scheduled release-auditor workflow (reverify last N releases) | Nightly/weekly job validates signatures + schema + checksum consistency |
| BL-007 | P1 | S | Metadata | Publish signed `release-index.json` across versions | File lists releases, key assets, and pointers to verification material |
| BL-008 | P0 | S | Operator security | Replace mutable tags with digest-pinned examples in all production docs | Deployment docs use digest-pinned images or explicit immutable references |
| BL-009 | P1 | S | Governance | Add "verification policy contract" document | Doc defines accepted OIDC issuer, identity regexes, and rotation procedure |
| BL-010 | P0 | S | Verification UX | Add no-`gh` verification fallback path (curl + cosign + jq) | Docs/scripts support environments without GitHub CLI |
| BL-011 | P1 | M | Packaging | Produce a trust-bundle archive for KMS releases (like locked-image) | KMS releases contain a single bundle with all trust artifacts |
| BL-012 | P1 | S | Packaging | Add `MANIFEST.txt` inside every trust bundle | Bundle lists filename, size, checksum, generation timestamp |
| BL-013 | P1 | S | Verification UX | Include release-level `verify_all.sh` script as an asset | One command verifies all relevant assets and signatures |
| BL-014 | P2 | S | Metadata | Add per-asset purpose labels in manifest | Manifest marks assets as required/optional by role (operator/auditor/dev) |
| BL-015 | P1 | S | Compatibility | Add a canonical compatibility map (`merod`, `kms`, policy entry) | Single JSON file captures version compatibility and is signed |
| BL-016 | P2 | M | Supply chain | Sign container metadata JSON that includes image digest/tags | Detached signatures available and verified in scripts |
| BL-017 | P1 | S | Naming consistency | Normalize release asset naming conventions across workflows | Names are consistent across KMS and locked-image releases |
| BL-018 | P1 | S | Docs UX | Add "minimal download set" section in verification docs | Docs show quick-verify vs full-audit asset subsets |
| BL-019 | P1 | S | Docs structure | Add docs index mapping source-of-truth files to operator docs | `docs/DOCS_INDEX.md` explains source files and ownership |
| BL-020 | P1 | M | Docs structure | Split docs by persona (operator, release engineer, security auditor, developer) | Landing page links persona paths and each has scoped runbooks |
| BL-021 | P1 | M | Trust communication | Add top-level "Trust & Verification" doc consolidating model | Hardware + supply chain + policy governance explained in one place |
| BL-022 | P1 | S | Trust communication | Standardize "what signatures prove / do not prove" section | All verification docs include same canonical explanation |
| BL-023 | P2 | M | Docs nav | Add docs navigation map and required anchor list | Maintainers can validate structure after edits |
| BL-024 | P1 | S | Process quality | Add docs update checklist tied to workflow changes | PRs touching workflows must update linked docs/checklist |
| BL-025 | P2 | M | Visualization | Add end-to-end sequence diagrams for both release pipelines | Diagrams included in docs and match workflow steps |
| BL-026 | P1 | S | Operations | Expand blue/green runbook into decision tree format | Runbook includes branching logic for failures and rollback |
| BL-027 | P1 | S | Verification UX | Add expected sample outputs from verification scripts | Operators can compare output with known-good examples |
| BL-028 | P0 | S | CI hardening | Add `actionlint` + `shellcheck` checks in CI | PRs fail on workflow/shell script lint errors |
| BL-029 | P1 | S | Release process | Add formal `CHANGELOG.md` and release taxonomy (stable/rc/hotfix) | Versioning policy documented and used in release workflow/docs |
| BL-030 | P0 | S | Governance | Add release-readiness checklist template for release PRs | Checklist required before release tag/publish |

---

## Implementation waves

### Wave 1 (start here, highest ROI)

1. BL-001 Release body template
2. BL-003 OCI provenance attestations
3. BL-006 Scheduled release-auditor workflow
4. BL-008 Digest-pinned deployment examples
5. BL-010 No-`gh` verification fallback
6. BL-028 actionlint + shellcheck CI
7. BL-030 Release-readiness checklist

### Wave 2

1. BL-004 SBOM generation + signing
2. BL-011 KMS trust bundle
3. BL-013 `verify_all.sh` release helper
4. BL-015 Compatibility map
5. BL-019 Docs source index
6. BL-020 Persona-based docs split
7. BL-022 Signature semantics standardization
8. BL-024 Docs update checklist
9. BL-027 Sample verification outputs
10. BL-029 Changelog + release taxonomy

### Wave 3

1. BL-002 Auto release note generation
2. BL-005 Rekor references in manifest
3. BL-012 `MANIFEST.txt` in bundles
4. BL-014 Asset purpose labels
5. BL-016 Signed container metadata JSON
6. BL-017 Naming normalization
7. BL-018 Minimal download-set docs
8. BL-021 Unified trust model page
9. BL-023 Docs nav map/anchors
10. BL-025 Pipeline sequence diagrams
11. BL-026 Blue/green decision tree

---

## Suggested first implementation batch

To begin execution safely with low disruption, implement in this order:

1. **BL-028** (CI lint gates)  
2. **BL-001** (release body template)  
3. **BL-030** (release-readiness checklist)  
4. **BL-008** (digest-pinned docs update)  

These changes are mostly additive and reduce risk for all later backlog items.

