# Architecture Graph

Visual map of KMS, mero-tee, regular nodes, and how they interact.

For the full diagram catalog, see [docs/diagrams/README.md](diagrams/README.md).
Mermaid sources: [`docs/diagrams/src/system-overview.mmd`](diagrams/src/system-overview.mmd), [`docs/diagrams/src/phala-attestation-sequence.mmd`](diagrams/src/phala-attestation-sequence.mmd).

## System overview

```mermaid
flowchart TB
    subgraph regular["Regular nodes (no TEE)"]
        MEROD_REG[merod]
    end

    subgraph phala["Phala lane (KMS plane)"]
        subgraph cvm["Phala CVM"]
            MEROD_PHALA[merod]
            KMS[mero-kms-phala]
            DSTACK[(dstack socket)]
        end
    end

    subgraph gcp["GCP lane (node image plane)"]
        PACKER[Packer build]
        NODE_IMG[node-image-gcp]
        MEROD_GCP[merod on TDX instance]
    end

    subgraph core["calimero-network/core"]
        MEROD_RUNTIME[merod runtime]
    end

    %% Regular nodes: no KMS
    MEROD_REG -->|"no key fetch"| MEROD_RUNTIME

    %% Phala flow: merod -> KMS -> dstack
    MEROD_PHALA -->|"1. POST /attest"| KMS
    MEROD_PHALA -->|"2. POST /challenge"| KMS
    MEROD_PHALA -->|"3. POST /get-key"| KMS
    KMS -->|"GetKey(path)"| DSTACK
    DSTACK -->|"key bytes"| KMS
    KMS -->|"storage key"| MEROD_PHALA

    %% GCP flow: build -> deploy -> verify
    PACKER -->|"locked image"| NODE_IMG
    NODE_IMG -->|"deploy"| MEROD_GCP
    MEROD_GCP -.->|"verify MRTD"| NODE_IMG
```

## Attestation flow (Phala KMS lane)

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
| **merod (Phala CVM)** | Node in TEE; fetches storage keys from KMS after mutual attestation |
| **mero-kms-phala** | Validates merod attestation, enforces policy, releases keys from dstack |
| **dstack** | Phala key system; deterministic key derivation by path |
| **node-image-gcp** | Locked merod images (Packer) for GCP TDX instances; MRTD/measurement verification |

## Platform lanes

| Lane | Responsibility |
|------|----------------|
| **Phala (KMS plane)** | Deploy mero-kms-phala; merod talks to KMS for key release |
| **GCP (node plane)** | Build/verify/deploy locked merod images; validate measurements |

See [trust-boundaries.md](architecture/trust-boundaries.md) for enforcement points and repository boundaries.
