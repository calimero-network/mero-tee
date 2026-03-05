# Workflow Setup

The GCP locked image build workflow requires GitHub repo configuration. **No secrets or credentials should be committed to the repo.**

## Required GitHub Repo Variables

Configure under Settings → Secrets and variables → Actions → Variables:

| Variable | Description |
|----------|-------------|
| `GCP_PACKER_PROJECT_ID` | GCP project for Packer |
| `PACKER_GCP_SOURCE_IMAGE` | Base image (e.g. ubuntu-2404) |
| `GCP_PACKER_REGION` | Region |
| `GCP_PACKER_ZONE` | Zone |
| `PACKER_GCP_SUBNETWORK` | Subnetwork URL |
| `GCP_ATTESTATION_PROJECT_ID` | Project for attestation VM |
| `GCP_ATTESTATION_ZONE` | Zone for attestation |
| `GCP_ATTESTATION_SUBNETWORK` | Subnetwork for attestation |
| `GCP_ATTESTATION_MACHINE_TYPE` | Machine type (e.g. c3-standard-4) |
| `GCP_ATTESTATION_ADMIN_API_PORT` | Admin API port (e.g. 80) |
| `GCP_ATTESTATION_ALLOWED_CIDRS` | CIDRs for attestation VM access |
| `GCP_ATTESTATION_CLEANUP_MAX_AGE_HOURS` | Cleanup age |
| `GCP_ATTESTATION_MEROD_VERSION` | Optional; defaults to latest core release |
| `ITA_APPRAISAL_URL` | Intel Trust Authority appraisal URL |
| `ITA_POLICY_IDS` | Policy IDs for attestation |
| `ITA_POLICY_MUST_MATCH` | Whether policy must match |

## Required GitHub Secrets

| Secret | Description |
|--------|-------------|
| `GCP_SERVICE_ACCOUNT_KEY` | JSON key for GCP (if not using WIF) |
| OR `GCP_WORKLOAD_IDENTITY_PROVIDER` + `GCP_PACKER_SERVICE_ACCOUNT_EMAIL` | For Workload Identity Federation |
| `ITA_API_KEY` | Intel Trust Authority API key (required for quote verification and MRTD publishing) |
| `GHCR_PUSH_TOKEN` (optional) | PAT for policy promotion PR creation when `github.token` PR creation is restricted |

## Trigger

The workflow runs on push to `master` when `packer/gcp/merod/versions.json` changes.

## KMS policy automation

Policy probe/promotion automation (`kms_policy_auto_pipeline.yaml`) reuses the
same secrets as `kms_staging_probe_phala.yaml`:

- `PHALA_CLOUD_API_KEY`
- `ITA_API_KEY`
