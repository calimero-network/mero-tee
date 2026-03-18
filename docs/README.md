# Documentation Portal

Single entry point for operators, release engineers, auditors, and maintainers.

## Start paths by audience

| Audience | Start here | Then go to |
|---|---|---|
| Operators | [Getting started](getting-started/README.md) | [Mero KMS TEE lane](runbooks/platforms/phala-kms.md), [Mero Node TEE lane](runbooks/platforms/gcp-merod.md) |
| Release engineers | [Release workflow setup](release/workflow-setup.md) | [Release taxonomy](release/taxonomy.md), [Release pipeline diagrams](release/pipeline-sequence-diagrams.md) |
| Auditors | [Trust and verification](release/trust-and-verification.md) | [Verification examples](release/verification-examples.md), [Trust boundaries](architecture/trust-boundaries.md) |
| Maintainers | [Canonical source map](reference/source-map.md) | [Reference index](reference/README.md), [ADRs](adr/README.md), [Glossary](GLOSSARY.md) |

## Documentation map

| Area | Purpose | Canonical docs |
|---|---|---|
| Getting started | Orientation and lane selection | [Getting started guide](getting-started/README.md), [Platform runbooks](runbooks/platforms/README.md) |
| Architecture | Trust model, boundaries, and high-level design | [Trust boundaries](architecture/trust-boundaries.md), [Architecture graph](DOCS_GRAPH.md) |
| Operations | Deployment and rollout procedures | [Operations index](operations/README.md), [KMS blue/green rollout](runbooks/operations/kms-blue-green-rollout.md) |
| Release and verification | Build/publish/verify release assets | [Trust and verification](release/trust-and-verification.md), [Workflow setup](release/workflow-setup.md), [Verification examples](release/verification-examples.md), [Minimal download sets](release/minimal-download-sets.md) |
| Policies | Policy promotion and attestation policy operations | [KMS policy pipeline](policies/kms-phala-policy-auto-pipeline.md), [KMS staging probe](policies/kms-phala-staging-probe.md), [Node image policy promotion](policies/node-image-gcp-policy-promotion.md) |
| Governance and reference | Terminology, decisions, and maintainer mappings | [Reference index](reference/README.md), [Canonical source map](reference/source-map.md), [ADR index](adr/README.md) |
| Visual docs | UML/flow/sequence/decision diagrams | [Diagrams hub](diagrams/README.md), [Operational decision flows](diagrams/operational-flows.md), [Release sequence diagrams](release/pipeline-sequence-diagrams.md) |
| Project boundaries | Responsibilities by project/folder | [Project boundaries](projects/README.md) |

## Architecture at a glance

```mermaid
flowchart LR
    subgraph KMS_TEE["Mero KMS TEE lane"]
        MEROD_KMS_TEE[merod]
        KMS[mero-kms-phala]
        DSTACK[(dstack)]
        MEROD_KMS_TEE -->|attest/challenge/get-key| KMS
        KMS -->|GetKey(path)| DSTACK
    end

    subgraph NODE_TEE["Mero Node TEE lane"]
        PACKER[Packer build]
        IMAGE[node-image-gcp]
        MEROD_NODE_TEE[merod on TDX]
        PACKER --> IMAGE --> MEROD_NODE_TEE
    end
```

For full flow detail, use [Diagrams hub](diagrams/README.md).

## Repository boundaries

Use [Project boundaries](projects/README.md) as the canonical responsibility map.

## Documentation conventions

- Keep one canonical page per topic; cross-link instead of duplicating.
- Keep maintainer source mapping in [reference/source-map.md](reference/source-map.md).
- For critical subsystems, provide context + sequence + operational decision diagrams.
