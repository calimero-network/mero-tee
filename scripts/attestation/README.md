# Attestation scripts

Shared tooling for verifying TDX quotes and turning them into measurement allowlists. The node-image and KMS release lanes both use it.

| Path | Purpose |
|------|---------|
| **`shared/`** | Dual-shape attest JSON (merod `data.quoteB64` and mero-kms `/attest` top-level `quoteB64`): Intel Trust Authority verification (`verify_tdx_quote_ita.py`) and policy candidate extraction (`extract_tdx_policy_candidates.py`). Used by **both** the node-image-gcp and the mero-kms (GCP TDX) release workflows. |

**Node-image release automation** (GCP image, published MRTDs, signatures) lives under `scripts/release/node-image-gcp/`, not here.

**KMS release automation** (two-replica cluster probe on the built KMS image, policy assembly, signatures) lives under `scripts/release/kms/`.
