# Repository restructure and naming proposal

This proposal defines a cleaner information architecture and naming scheme for
`mero-tee` based on current pain points:

- mixed naming styles (`mero-kms-phala`, `merod-locked-image`, `locked-image`)
- mixed separators (`snake_case` workflow files, `kebab-case` assets/scripts)
- flat docs surface where platform runbooks, release docs, and design docs are
  interleaved
- ambiguous "deploy on X" wording that hides different responsibilities

---

## 1) Naming principles

1. **Name by responsibility first**, platform second.
2. **One canonical prefix per release family**.
3. **Use kebab-case for files/docs/scripts/workflow filenames**.
4. **Avoid overloaded terms** like "locked-image" without scope (node image).
5. **Keep `core` vs `mero-tee` responsibility explicit** in docs.

---

## 2) Canonical domain vocabulary

Use two explicit lanes everywhere:

- **`kms-phala` lane** (KMS service and related policy/release assets)
- **`node-image-gcp` lane** (locked `merod` image build/release assets)

Avoid mixing lane names inside one artifact family.

---

## 3) Proposed rename map (services/assets/workflows/scripts)

## Services and policy registries

| Current | Proposed |
|---|---|
| `mero-kms-phala` (service name) | `kms-phala` (short canonical lane name) |
| `policies/mero-kms-phala/` | `policies/kms-phala/` |
| `policies/merod-locked-image/` | `policies/node-image-gcp/` |

## Release asset prefixes

| Current | Proposed |
|---|---|
| `mero-kms-phala-*` | `kms-phala-*` |
| `merod-locked-image-*` | `node-image-gcp-*` |
| `locked-image-vX.Y.Z` tag | `node-image-gcp-vX.Y.Z` tag |

## Workflow filenames

| Current | Proposed |
|---|---|
| `release-mero-kms-phala.yaml` | `release-kms-phala.yaml` |
| `gcp_locked_image_build.yaml` | `release-node-image-gcp.yaml` |
| `kms_staging_probe_phala.yaml` | `kms-phala-staging-probe.yaml` |
| `kms_policy_promotion_pr.yaml` | `kms-phala-policy-promotion-pr.yaml` |
| `locked_image_policy_promotion_pr.yaml` | `node-image-gcp-policy-promotion-pr.yaml` |

## Script names

| Current | Proposed |
|---|---|
| `verify_mero_kms_release_assets.sh` | `verify-kms-phala-release-assets.sh` |
| `verify_locked_image_release_assets.sh` | `verify-node-image-gcp-release-assets.sh` |
| `verify_all_release_assets.sh` | `verify-release-assets.sh` |
| `apply_merod_kms_attestation_config.sh` | `apply-merod-kms-phala-attestation-config.sh` |
| `generate_merod_kms_attestation_config.sh` | `generate-merod-kms-phala-attestation-config.sh` |

---

## 4) Proposed repository structure

```text
docs/
  architecture/
    trust-boundaries.md
    attestation-enforcement.md
  runbooks/
    platforms/
      phala-kms.md
      gcp-node-image.md
    operations/
      kms-blue-green-rollout.md
  release/
    verification-beginner.md
    verification-examples.md
    taxonomy.md
    pipeline-sequence-diagrams.md
  policies/
    kms-phala-policy-promotion.md
    kms-phala-policy-auto-pipeline.md
    node-image-gcp-policy-promotion.md

scripts/
  release/
    verify-kms-phala-release-assets.sh
    verify-node-image-gcp-release-assets.sh
    verify-release-assets.sh
  policy/
    read-kms-phala-policy-registry.sh
    read-node-image-gcp-policy-registry.sh
    apply-merod-kms-phala-attestation-config.sh
    generate-merod-kms-phala-attestation-config.sh

policies/
  index.json
  kms-phala/
  node-image-gcp/
```

---

## 5) Execution plan (breaking changes allowed)

### Phase A: naming baseline (low-medium risk)

- Rename workflow files to canonical kebab-case names.
- Rename script files to canonical names.
- Rename policy directories.
- Update all workflow references and docs in one batch.

### Phase B: release surface normalization (medium-high risk)

- Rename release asset prefixes to `kms-phala-*` and `node-image-gcp-*`.
- Switch node-image tag format to `node-image-gcp-vX.Y.Z`.
- Update all verifiers and release workflows together.

### Phase C: docs tree split by intent (medium risk)

- Move docs into `architecture/`, `runbooks/`, `release/`, `policies/`.
- Keep top-level index files only as curated entrypoints.

---

## 6) Guardrails to add with restructure

- CI check: forbid introducing old prefixes (`mero-kms-phala-`, `merod-locked-image-`) after migration cutover.
- CI check: workflow/script filenames must be kebab-case.
- CI check: docs links must target canonical runbook paths.

---

## 7) Recommended order

1. Phase A (workflow/script/policy path naming)
2. Phase C (docs tree restructure)
3. Phase B (asset/tag rename), because it impacts release consumers most

This order reduces release disruption while making internal structure coherent
early.
