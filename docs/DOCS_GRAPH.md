# Documentation Graph

Visual map of mero-tee documentation structure and relationships. Use this to navigate the docs and understand how topics connect.

## Graph

```mermaid
flowchart TB
    subgraph entry["Entry points"]
        README[README.md]
        DOCS_INDEX[DOCS_INDEX.md]
        DOCS_NAV[DOCS_NAVIGATION_MAP.md]
    end

    subgraph architecture["Architecture"]
        TB[trust-boundaries.md]
        KMS_PROP[phala-kms-key-protection-proposal.md]
        DIRECT_KMS[phala-direct-kms-design.md]
        MIGRATION[migration-plan.md]
    end

    subgraph release["Release & verification"]
        TRUST[trust-and-verification.md]
        BEGINNER[verification-beginner.md]
        EXAMPLES[verification-examples.md]
        PIPELINE[pipeline-sequence-diagrams.md]
        WORKFLOW[workflow-setup.md]
        TAXONOMY[taxonomy.md]
        MINIMAL[minimal-download-sets.md]
    end

    subgraph runbooks_platforms["Platform runbooks"]
        PLAT_README[platforms/README.md]
        PHALA[phala-kms.md]
        GCP[gcp-merod.md]
    end

    subgraph runbooks_ops["Operations runbooks"]
        VERIFY_MRTD[verify-mrtd.md]
        BLUE_GREEN[kms-blue-green-rollout.md]
    end

    subgraph policies["Policy workflows"]
        STAGING[kms-phala-staging-probe.md]
        PROMO[kms-phala-policy-promotion.md]
        AUTO[kms-phala-policy-auto-pipeline.md]
        NODE_PROMO[node-image-gcp-policy-promotion.md]
        ATTEST_TASK[kms-phala-attestation-task-list.md]
    end

    subgraph meta["Meta / proposals"]
        RESTRUCTURE[REPO_RESTRUCTURE_PROPOSAL.md]
    end

    %% Entry point links
    README --> PLAT_README
    README --> TB
    README --> DOCS_INDEX
    DOCS_INDEX --> DOCS_NAV

    %% Architecture is central
    TB --> PLAT_README
    TB --> PHALA
    TB --> GCP
    TB --> TRUST

    %% Release trust flow
    TRUST --> BEGINNER
    TRUST --> PLAT_README
    TRUST --> VERIFY_MRTD
    TRUST --> EXAMPLES
    TRUST --> TB
    BEGINNER --> VERIFY_MRTD

    %% Platform runbooks
    PLAT_README --> PHALA
    PLAT_README --> GCP
    PHALA --> TB
    PHALA --> BLUE_GREEN
    GCP --> TB
    GCP --> VERIFY_MRTD

    %% Operations
    BLUE_GREEN --> STAGING
    VERIFY_MRTD --> TB

    %% Policy chain
    STAGING --> PROMO
    PROMO --> AUTO
    ATTEST_TASK --> PHALA

    %% Release automation
    PIPELINE --> WORKFLOW
    WORKFLOW --> TRUST
```

## Legend

| Category | Purpose |
|----------|---------|
| **Entry points** | Repository root and maintainer indexes |
| **Architecture** | Trust boundaries, design proposals, migration plans |
| **Release & verification** | Trust model, verification flows, release taxonomy |
| **Platform runbooks** | Phala KMS vs GCP node-image deployment lanes |
| **Operations runbooks** | MRTD verification, KMS blue/green rollout |
| **Policy workflows** | KMS policy staging, promotion, attestation tasks |
| **Meta** | Repo structure proposals |

## Quick reference by role

| Role | Start here |
|------|------------|
| **Operator** | [trust-and-verification.md](release/trust-and-verification.md) → [platforms/README.md](runbooks/platforms/README.md) |
| **First-time verifier** | [verification-beginner.md](release/verification-beginner.md) |
| **Release engineer** | [pipeline-sequence-diagrams.md](release/pipeline-sequence-diagrams.md) → [workflow-setup.md](release/workflow-setup.md) |
| **Maintainer** | [DOCS_INDEX.md](DOCS_INDEX.md) → [trust-boundaries.md](architecture/trust-boundaries.md) |
