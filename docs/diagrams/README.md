# Diagrams Hub

Central index for architecture, sequence, and operational decision diagrams.

## Coverage matrix

Each critical area should expose all three diagram types:

| Area | Context diagram | Sequence diagram | Operational/decision flow |
|---|---|---|---|
| Phala KMS lane | [System overview](../DOCS_GRAPH.md#system-overview) | [Attestation flow](../DOCS_GRAPH.md#attestation-flow-phala-kms-lane) | [KMS blue/green decision tree](../runbooks/operations/kms-blue-green-rollout.md#decision-tree) |
| GCP node-image lane | [System overview](../DOCS_GRAPH.md#system-overview) | [node-image release sequence](../release/pipeline-sequence-diagrams.md#2-release-node-image-gcpyaml) | [GCP rollout flow](operational-flows.md#gcp-node-image-verification-and-rollout) |
| Release governance | [Architecture graph](../DOCS_GRAPH.md) | [Release pipeline sequences](../release/pipeline-sequence-diagrams.md) | [Release verification triage](operational-flows.md#release-asset-verification-triage) |

## Diagram pages

- [Architecture graph](../DOCS_GRAPH.md)
- [Release pipeline sequence diagrams](../release/pipeline-sequence-diagrams.md)
- [Operational decision flows](operational-flows.md)

## Mermaid source files

All source snippets live in [`docs/diagrams/src/`](src/):

- [system-overview.mmd](src/system-overview.mmd)
- [phala-attestation-sequence.mmd](src/phala-attestation-sequence.mmd)
- [release-kms-sequence.mmd](src/release-kms-sequence.mmd)
- [release-node-image-sequence.mmd](src/release-node-image-sequence.mmd)
- [release-audit-sequence.mmd](src/release-audit-sequence.mmd)
- [kms-blue-green-decision-flow.mmd](src/kms-blue-green-decision-flow.mmd)

## Authoring guidance

- Prefer Mermaid in Markdown for versioned reviewability.
- Keep diagram names stable to avoid broken deep links.
- Update source files in `src/` when changing rendered diagrams.
- When diagram semantics change, update linked runbooks/release docs in the same PR.
