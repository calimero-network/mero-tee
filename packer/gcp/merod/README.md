# GCP Packer Merod Image Build

Builds locked merod node images for GCP TDX Confidential VMs.

## Profiles

- **debug** – Full merod, no lockdown
- **debug-read-only** – Read-only merod, no lockdown
- **locked-read-only** – Read-only merod with lockdown (no SSH, no getty, etc.)

## Prerequisites

- Packer
- Ansible
- GCP credentials (service account or Workload Identity)

## Configuration

Configure via GitHub repo variables or environment:

- `GCP_PACKER_PROJECT_ID`, `PACKER_GCP_SOURCE_IMAGE`, `GCP_PACKER_REGION`, `GCP_PACKER_ZONE`
- `GCP_ATTESTATION_*` for attestation VM
- `ITA_APPRAISAL_URL`, `ITA_POLICY_IDS` for attestation verification

## Build

```bash
cd packer/gcp/merod
packer build -var-file=ubuntu-intel.pkrvars.hcl ubuntu.pkr.hcl
```

## Release

The GitHub workflow `gcp_locked_image_build.yaml` builds images, runs attestation, and publishes MRTDs, attestation artifacts, and provenance to releases. Configure repo variables and secrets before running.
