# Documentation Portal

Single entry point for operators, release engineers, auditors, and maintainers.

## Start paths by audience

| Audience | Start here | Then go to |
|---|---|---|
| Operators | [Platform runbooks](runbooks/platforms/README.md) | [Phala KMS lane](runbooks/platforms/phala-kms.md), [GCP node lane](runbooks/platforms/gcp-merod.md) |
| Release engineers | [Release workflow setup](release/workflow-setup.md) | [Release taxonomy](release/taxonomy.md), [Release pipeline diagrams](release/pipeline-sequence-diagrams.md) |
| Auditors | [Trust and verification](release/trust-and-verification.md) | [Verification examples](release/verification-examples.md), [Trust boundaries](architecture/trust-boundaries.md) |
| Maintainers | [Source index](DOCS_INDEX.md) | [Navigation map](DOCS_NAVIGATION_MAP.md), [ADRs](adr/README.md), [Glossary](GLOSSARY.md) |

## Documentation map

| Area | Purpose | Canonical docs |
|---|---|---|
| Getting started | Orientation and lane selection | [Platform runbooks](runbooks/platforms/README.md) |
| Architecture | Trust model, boundaries, and high-level design | [Trust boundaries](architecture/trust-boundaries.md), [Architecture graph](DOCS_GRAPH.md) |
| Operations | Deployment and rollout procedures | [Phala KMS runbook](runbooks/platforms/phala-kms.md), [GCP node runbook](runbooks/platforms/gcp-merod.md), [KMS blue/green rollout](runbooks/operations/kms-blue-green-rollout.md) |
| Release and verification | Build/publish/verify release assets | [Trust and verification](release/trust-and-verification.md), [Workflow setup](release/workflow-setup.md), [Verification examples](release/verification-examples.md), [Minimal download sets](release/minimal-download-sets.md) |
| Policies | Policy promotion and attestation policy operations | [KMS policy pipeline](policies/kms-phala-policy-auto-pipeline.md), [KMS staging probe](policies/kms-phala-staging-probe.md), [Node image policy promotion](policies/node-image-gcp-policy-promotion.md) |
| Governance | Terminology and accepted decisions | [Glossary](GLOSSARY.md), [ADR index](adr/README.md) |
| Visual docs | UML/flow/sequence diagrams | [Diagrams hub](diagrams/README.md), [Architecture graph](DOCS_GRAPH.md), [Release sequence diagrams](release/pipeline-sequence-diagrams.md) |

## Architecture at a glance

```mermaid
flowchart LR
    subgraph PHALA["Phala lane (KMS plane)"]
        MEROD_PHALA[merod]
        KMS[mero-kms-phala]
        DSTACK[(dstack)]
        MEROD_PHALA -->|attest/challenge/get-key| KMS
        KMS -->|GetKey(path)| DSTACK
    end

    subgraph GCP["GCP lane (node image plane)"]
        PACKER[Packer build]
        IMAGE[node-image-gcp]
        MEROD_GCP[merod on TDX]
        PACKER --> IMAGE --> MEROD_GCP
    end
```

For full flow detail, use [Diagrams hub](diagrams/README.md).

## Repository boundaries

Every major folder here is treated as its own project area with a separate responsibility:

- [Root README](../README.md): platform-level overview and release trust model.
- [mero-kms/README.md](../mero-kms/README.md): KMS implementation details.
- [mero-tee/README.md](../mero-tee/README.md): node image build/deploy details.
- [attestation-verifier/README.md](../attestation-verifier/README.md): verifier app details.

## Documentation conventions

- Keep one canonical page per topic; cross-link instead of duplicating.
- Include at least one diagram for architecture and one for critical runtime/release flow.
- Update [DOCS_INDEX.md](DOCS_INDEX.md) when adding or moving docs.
