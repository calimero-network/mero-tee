# KMS staging probe workflow (Phala)

This workflow automates collection of candidate KMS attestation policy values from a temporary Phala CVM.

Workflow file:

- `.github/workflows/kms_staging_probe_phala.yaml`

## What it does

1. Deploys an ephemeral CVM running `mero-kms-phala` from a provided image.
2. Waits for `GET /health`.
3. Calls `POST /attest` with a fresh nonce.
4. Verifies the quote via Intel Trust Authority (`scripts/verify_tdx_quote_ita.py`).
5. Extracts candidate policy values (`scripts/extract_tdx_policy_candidates.py`) and writes:
   - `kms-policy-candidates.json` (canonical candidate policy payload),
   - `kms-policy-candidates.env` (compatibility/env export form).
6. Uploads full probe artifacts.
7. Always deletes the ephemeral CVM during cleanup (on both success and failure paths).

When resolving from a release tag, the workflow first validates that the release
manifest declares `verification.kms_attest_endpoint == "/attest"`.

## Required GitHub secrets

- `PHALA_CLOUD_API_KEY` – API key for Phala Cloud CLI auth.
- `ITA_API_KEY` – Intel Trust Authority API key.

## Running it

This workflow is used by the automatic pipeline (`kms_policy_auto_pipeline.yaml`)
and can also be run manually (`workflow_dispatch`) with:

- `kms_release_tag`:
  - explicit release tag (recommended, for example `2.1.3`), or
  - `latest` (default) to auto-use the latest GitHub release tag (staging convenience only)
- optional `kms_image` override pinned to a reviewed tag/digest that includes `/attest`
  (for example `ghcr.io/calimero-network/mero-kms-phala:pr-1`)
- optional `region`
- optional `ita_policy_ids`
- optional `kms_url_override` if your endpoint format differs from default derivation

Do not use mutable container tag `:latest` for `kms_image` overrides.

## Outputs

The workflow uploads an artifact bundle `kms-staging-probe-<run_id>-<attempt>` containing:

- deployment metadata (`phala-deploy.json`, `phala-cvm.json`, ...)
- `/attest` request/response
- ITA verification artifacts (`external-verification-*.json`, token claims, `mrtd.json`)
- generated policy candidates:
  - `kms-policy-candidates.json`
  - `kms-policy-candidates.env`
- run summary metadata, including candidate values and probe context

## Promotion to governed policy PR

After collecting probe artifacts, run:

- `.github/workflows/kms_policy_promotion_pr.yaml`

with the probe run ID and target release tag. This creates/updates:

- `policies/mero-kms-phala/<tag>.json`
- `policies/mero-kms-phala/index.json`

in a pull request for review before release publication.

After merge, release automation reads this policy registry entry for the same
release tag. Repository variable updates are no longer required for policy
allowlist publication.
