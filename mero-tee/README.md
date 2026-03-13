# GCP Packer Merod Image Build

Builds locked merod node images for GCP TDX Confidential VMs.

## Profiles

- **debug** – Full merod, no lockdown
- **debug-read-only** – Read-only merod, no lockdown
- **locked-read-only** – Read-only merod with lockdown (no SSH, no getty, etc.)

Security intent:

- `locked-read-only` is the production baseline.
- `debug` and `debug-read-only` are for non-production cohorts and should use separate non-production KMS policy/key lanes.
- KMS releases publish profile-specific policy assets so operators can enforce profile-to-profile trust cohorts.

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
cd mero-tee
packer build -var-file=ubuntu-intel.pkrvars.hcl ubuntu.pkr.hcl
```

## Release

The GitHub workflow `release-node-image-gcp.yaml` builds images, runs attestation, and publishes MRTDs, attestation artifacts, and provenance to releases. Configure repo variables and secrets before running.
