# Architecture Graph

Visual map of KMS, mero-tee, regular nodes, and how they interact.

For the full diagram catalog, see [docs/diagrams/README.md](diagrams/README.md).
Mermaid sources: [`docs/diagrams/src/system-overview.mmd`](diagrams/src/system-overview.mmd), [`docs/diagrams/src/mero-kms-tee-attestation-sequence.mmd`](diagrams/src/mero-kms-tee-attestation-sequence.mmd).

## System overview

```mermaid
flowchart TB
    subgraph regular["Regular nodes (no TEE)"]
        MEROD_REG[merod]
    end

    subgraph kms_tee["Mero KMS TEE lane"]
        subgraph cvm["KMS TEE environment"]
            MEROD_KMS_TEE[merod]
            KMS[mero-kms-phala]
            DSTACK[(dstack socket)]
        end
    end

    subgraph node_tee["Mero Node TEE lane"]
        PACKER[Packer build]
        NODE_IMG[node-image-gcp]
        MEROD_NODE_TEE[merod on TDX instance]
    end

    subgraph core["calimero-network/core"]
        MEROD_RUNTIME[merod runtime]
    end

    %% Regular nodes: no KMS
    MEROD_REG -->|"no key fetch"| MEROD_RUNTIME

    %% Mero KMS TEE flow: merod -> KMS -> dstack
    MEROD_KMS_TEE -->|"1. POST /attest"| KMS
    MEROD_KMS_TEE -->|"2. POST /challenge"| KMS
    MEROD_KMS_TEE -->|"3. POST /get-key"| KMS
    KMS -->|"GetKey(path)"| DSTACK
    DSTACK -->|"key bytes"| KMS
    KMS -->|"storage key"| MEROD_KMS_TEE

    %% Mero Node TEE flow: build -> deploy -> verify
    PACKER -->|"locked image"| NODE_IMG
    NODE_IMG -->|"deploy"| MEROD_NODE_TEE
    MEROD_NODE_TEE -.->|"verify MRTD"| NODE_IMG
```

## Attestation flow (Mero KMS TEE lane)

```mermaid
sequenceDiagram
    participant M as merod (in CVM)
    participant K as mero-kms-phala
    participant D as dstack

    M->>K: POST /attest (nonce)
    K->>M: quoteB64
    Note over M: Verify KMS quote + policy
    M->>K: POST /challenge (peerId)
    K->>M: challengeId, nonce
    M->>K: POST /get-key (quote, signature)
    Note over K: Verify node quote + policy
    K->>D: GetKey(path)
    D->>K: key bytes
    K->>M: storage key
```

## Component roles

| Component | Role |
|-----------|------|
| **merod (regular)** | Node runtime; no TEE, no storage key fetch from KMS |
| **merod (KMS TEE environment)** | Node in TEE; fetches storage keys from KMS after mutual attestation |
| **mero-kms-phala** | Validates merod attestation, enforces policy, releases keys from dstack |
| **dstack** | Key system used by the KMS TEE lane; deterministic key derivation by path |
| **node-image-gcp** | Locked merod images (Packer) for Node TEE instances; MRTD/measurement verification |

## Platform lanes

| Lane | Responsibility |
|------|----------------|
| **Mero KMS TEE** | Deploy mero-kms-phala; merod talks to KMS for key release |
| **Mero Node TEE** | Build/verify/deploy locked merod images; validate measurements |

See [trust-boundaries.md](architecture/trust-boundaries.md) for enforcement points and repository boundaries.
