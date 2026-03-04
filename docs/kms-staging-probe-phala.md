# KMS staging probe workflow (Phala)

This workflow automates collection of candidate KMS attestation policy values from a temporary Phala CVM.

Workflow file:

- `.github/workflows/kms_staging_probe_phala.yaml`

## What it does

1. Deploys an ephemeral CVM running `mero-kms-phala` from a provided image.
2. Waits for `GET /health`.
3. Calls `POST /attest` with a fresh nonce.
4. Verifies the quote via Intel Trust Authority (`scripts/verify_tdx_quote_ita.py`).
5. Extracts candidate policy values (`scripts/extract_tdx_policy_candidates.py`) for:
   - `MERO_KMS_ALLOWED_TCB_STATUSES_JSON`
   - `MERO_KMS_ALLOWED_MRTD_JSON`
   - `MERO_KMS_ALLOWED_RTMR0_JSON`
   - `MERO_KMS_ALLOWED_RTMR1_JSON`
   - `MERO_KMS_ALLOWED_RTMR2_JSON`
   - `MERO_KMS_ALLOWED_RTMR3_JSON`
6. Uploads full probe artifacts.
7. Deletes the CVM unless `keep_cvm=true`.

## Required GitHub secrets

- `PHALA_CLOUD_API_KEY` – API key for Phala Cloud CLI auth.
- `ITA_API_KEY` – Intel Trust Authority API key.

## Running it

Run the workflow manually (`workflow_dispatch`) and provide:

- `kms_image` pinned to a reviewed tag/digest that includes `/attest`
  (for example `ghcr.io/calimero-network/mero-kms-phala:pr-1`)
- optional `region`
- optional `ita_policy_ids`
- optional `kms_url_override` if your endpoint format differs from default derivation

Do not use mutable `:latest` for this workflow.

## Outputs

The workflow uploads an artifact bundle `kms-staging-probe-<run_id>-<attempt>` containing:

- deployment metadata (`phala-deploy.json`, `phala-cvm.json`, ...)
- `/attest` request/response
- ITA verification artifacts (`external-verification-*.json`, token claims, `mrtd.json`)
- generated policy candidates:
  - `kms-policy-candidates.json`
  - `kms-policy-candidates.env`

The run summary also prints copy/paste-ready `MERO_KMS_ALLOWED_*_JSON` values.

## Promotion to governed policy PR

After collecting probe artifacts, run:

- `.github/workflows/kms_policy_promotion_pr.yaml`

with the probe run ID and target release tag. This creates/updates:

- `policies/mero-kms-phala/<tag>.json`
- `policies/mero-kms-phala/index.json`

in a pull request for review before release publication.
