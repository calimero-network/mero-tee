# Release Pipeline Sequence Diagrams

This document visualizes the main release paths and verification loops.

## 1) `release-kms-phala.yaml`

```mermaid
sequenceDiagram
  autonumber
  participant Maintainer
  participant GitHubActions
  participant GHCR
  participant GitHubRelease
  participant Sigstore
  participant Rekor

  Maintainer->>GitHubActions: Push release tag (X.Y.Z)
  GitHubActions->>GitHubActions: Build platform binaries
  GitHubActions->>GHCR: Build + push container image
  GitHubActions->>GitHubActions: Generate checksums + manifest + policy + compatibility map + SBOMs
  GitHubActions->>Sigstore: keyless sign blobs (cosign sign-blob)
  Sigstore->>Rekor: transparency log entries
  GitHubActions->>GitHubActions: Build Rekor index + trust bundle
  GitHubActions->>GitHubActions: Verify generated signatures
  GitHubActions->>GitHubRelease: Upload signed assets + release notes
  GitHubActions->>GitHubActions: Smoke-test with verify script
```

## 2) `release-node-image-gcp.yaml`

```mermaid
sequenceDiagram
  autonumber
  participant Maintainer
  participant GitHubActions
  participant GCP
  participant GitHubRelease
  participant Sigstore

  Maintainer->>GitHubActions: Trigger workflow for tag (X.Y.Z)
  GitHubActions->>GCP: Build profile images (debug/debug-ro/locked-ro)
  GitHubActions->>GitHubActions: Extract MRTDs + build policy/provenance
  GitHubActions->>GitHubActions: Generate checksums + attestation bundle + SBOM
  GitHubActions->>Sigstore: keyless sign all release assets
  GitHubActions->>GitHubActions: Verify signatures
  GitHubActions->>GitHubRelease: Upload release assets + notes
  GitHubActions->>GitHubActions: Smoke-test with node-image-gcp verifier
```

## 3) Scheduled release audit (`release-auditor.yaml`)

```mermaid
sequenceDiagram
  autonumber
  participant Scheduler
  participant AuditorWorkflow
  participant GitHubReleases
  participant VerifierScripts

  Scheduler->>AuditorWorkflow: Weekly cron / manual dispatch
  AuditorWorkflow->>GitHubReleases: List recent releases
  loop each tag
    AuditorWorkflow->>GitHubReleases: Inspect asset set
    alt KMS assets present
      AuditorWorkflow->>VerifierScripts: verify-kms-phala-release-assets.sh
    end
    alt node-image-gcp assets present
      AuditorWorkflow->>VerifierScripts: verify-node-image-gcp-release-assets.sh
    end
  end
  AuditorWorkflow->>AuditorWorkflow: Publish summary + fail on mismatches
```
