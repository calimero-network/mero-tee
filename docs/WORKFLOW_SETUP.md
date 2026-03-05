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

## PR documentation guard

Pull requests that modify any of the following paths must also include a
documentation update in `docs/**` or `README.md`:

- `.github/workflows/**`
- `scripts/**`
- `packer/**`

This policy is enforced by `.github/workflows/docs-update-guard.yaml`.

## KMS policy automation

Policy probe/promotion automation (`kms_policy_auto_pipeline.yaml`) reuses the
same secrets as `kms_staging_probe_phala.yaml`:

- `PHALA_CLOUD_API_KEY`
- `ITA_API_KEY`

Locked-image policy promotion (`locked_image_policy_promotion_pr.yaml`) reads
release assets and opens a policy PR. For repositories where `github.token`
cannot open PRs, ensure `GHCR_PUSH_TOKEN` is configured.

`gcp_locked_image_build.yaml` auto-dispatches this promotion workflow after
publishing release assets.

## Release SBOM assets

Release workflows now install Syft and publish signed SPDX SBOM assets together
with the existing release checksums/manifest artifacts.

- `gcp_locked_image_build.yaml` publishes
  `locked-image-release-sbom.spdx.json` (plus matching `.sig` and `.pem`
  assets) and includes it in `locked-image-checksums.txt`.
- `release-mero-kms-phala.yaml` publishes:
  - `mero-kms-phala-container-sbom.spdx.json`
  - `mero-kms-phala-binaries-sbom.spdx.json`
  - matching `.sig` and `.pem` files for each SBOM

## Auto-generated release notes metadata

Release workflows generate release notes from workflow metadata and publish them
as the GitHub Release body (`body_path`).

- `release-mero-kms-phala.yaml` includes:
  - tag and commit SHA
  - workflow run reference
  - container digest reference
  - compatibility/policy source pointers
  - verification command snippets
- `gcp_locked_image_build.yaml` includes:
  - tag and commit SHA
  - workflow run reference
  - profile MRTD summary
  - verification command snippets
