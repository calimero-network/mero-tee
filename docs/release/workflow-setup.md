# Workflow Setup

The GCP node-image build workflow requires GitHub repo configuration. **No secrets or credentials should be committed to the repo.**

## Required GitHub Repo Variables

Configure under Settings → Secrets and variables → Actions → Variables:

| Variable | Description |
|----------|-------------|
| `GCP_PACKER_PROJECT_ID` | GCP project for Packer |
| `PACKER_GCP_SOURCE_IMAGE` | Base image (e.g. ubuntu-2510) |
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

## Base image notes

Current builds use Ubuntu 25.10 (Questing Quokka) for kernel 6.17+ (RTMR3 sysfs support). When unset, `PACKER_GCP_SOURCE_IMAGE` causes Packer to use the `ubuntu-2510-amd64` image family.

**Ubuntu 26.04 LTS availability**: Based on discussions in the Ubuntu community, Ubuntu 26.04 LTS is expected to be part of the official Ubuntu repositories by March 2026, with components like authd maintained by Canonical for this release. When available, consider migrating to `ubuntu-2604-lts-amd64` for longer support.

## Required GitHub Secrets

| Secret | Description |
|--------|-------------|
| `GCP_SERVICE_ACCOUNT_KEY` | JSON key for GCP (if not using WIF) |
| OR `GCP_WORKLOAD_IDENTITY_PROVIDER` + `GCP_PACKER_SERVICE_ACCOUNT_EMAIL` | For Workload Identity Federation |
| `ITA_API_KEY` | Intel Trust Authority API key (required for quote verification and MRTD publishing) |
| `GHCR_PUSH_TOKEN` (optional) | PAT for policy promotion PR creation when `github.token` PR creation is restricted |

## Trigger

The workflow runs on push to `master` when `mero-tee/versions.json` changes.

## PR documentation guard

Pull requests that modify any of the following paths must also include a
documentation update in `docs/**` or `README.md`:

- `.github/workflows/**`
- `scripts/release/**`
- `scripts/policy/**`
- `scripts/attestation/**`
- `mero-tee/**`

This policy is enforced by `.github/workflows/docs-update-guard.yaml`.

## Release version sync guard

`release-version-sync-guard.yaml` enforces that KMS and merod release versions
are bumped together.

It validates the following are synchronized for the active release version:

- `mero-kms/Cargo.toml` package version
- `Cargo.lock` `mero-kms-phala` package version
- `mero-tee/versions.json` `imageVersion`
- `policies/index.json` release entry for that version
- `policies/kms-phala/<version>.json`
- `policies/mero-tee/<version>.json`

For `policies/index.json`, `node_image_tag` must be:

- `mero-tee-v<version>`

And `kms_tag` must be:

- `mero-kms-v<version>`

This keeps release metadata aligned with node-image release tags.

## KMS policy operations

KMS policy generation/rollout currently uses staging probes plus policy scripts.
Operationally, treat `kms-phala-staging-probe.yaml` and `scripts/policy/*.sh` as
the canonical execution path.

These operations reuse:

- `PHALA_CLOUD_API_KEY`
- `ITA_API_KEY`

## Release SBOM assets

Release workflows now install Syft and publish signed SPDX SBOM assets together
with the existing release checksums/manifest artifacts.

- `release-node-image-gcp.yaml` publishes
  `node-image-gcp-release-sbom.spdx.json` (plus matching `.sig` and `.pem`
  assets) and includes it in `node-image-gcp-checksums.txt`.
- `release-kms-phala.yaml` publishes:
  - `kms-phala-container-sbom.spdx.json`
  - `kms-phala-binaries-sbom.spdx.json`
  - matching `.sig` and `.pem` files for each SBOM

## Auto-generated release notes metadata

Release workflows generate release notes from workflow metadata and publish them
as the GitHub Release body (`body_path`).

- `release-kms-phala.yaml` includes:
  - tag and commit SHA
  - workflow run reference
  - container digest reference
  - compatibility/policy source pointers
  - verification command snippets
- `release-node-image-gcp.yaml` includes:
  - tag and commit SHA
  - workflow run reference
  - profile MRTD summary
  - verification command snippets

## Workflow modularization layout

To keep release workflows reviewable, large inline shell blocks are extracted into
versioned scripts:

- KMS release lane: `scripts/release/kms-phala/*.sh`
- Node-image release lane: `scripts/release/node-image-gcp/*.sh`

The workflows call these scripts directly, and CI runs syntax/lint checks on them.
When changing release behavior, update both the script and this documentation.
