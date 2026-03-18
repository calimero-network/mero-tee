# Diagrams Hub

Central index for visual documentation (system context, sequence diagrams, and operational flows).

## Diagram index

| Diagram | Type | Primary page |
|---|---|---|
| System overview (KMS, mero-tee, nodes) | Context/flowchart | [docs/DOCS_GRAPH.md#system-overview](../DOCS_GRAPH.md#system-overview) |
| Attestation flow (Phala KMS lane) | Sequence | [docs/DOCS_GRAPH.md#attestation-flow-phala-kms-lane](../DOCS_GRAPH.md#attestation-flow-phala-kms-lane) |
| KMS release workflow | Sequence | [docs/release/pipeline-sequence-diagrams.md#1-release-kms-phalayaml](../release/pipeline-sequence-diagrams.md#1-release-kms-phalayaml) |
| node-image-gcp release workflow | Sequence | [docs/release/pipeline-sequence-diagrams.md#2-release-node-image-gcpyaml](../release/pipeline-sequence-diagrams.md#2-release-node-image-gcpyaml) |
| Scheduled release audit loop | Sequence | [docs/release/pipeline-sequence-diagrams.md#3-scheduled-release-audit-release-auditoryaml](../release/pipeline-sequence-diagrams.md#3-scheduled-release-audit-release-auditoryaml) |

## Required coverage

For each critical subsystem or workflow, maintain:

1. One context diagram (components + trust boundaries)
2. One sequence diagram (happy path)
3. One operational/decision flow (rollout or failure handling)

## Diagram authoring guidance

- Prefer Mermaid in Markdown for versioned reviewability.
- Keep diagram naming stable to avoid broken deep links.
- When diagram semantics change, update linked runbooks/release docs in the same PR.
