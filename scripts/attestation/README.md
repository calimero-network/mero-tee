# Attestation scripts

Layout separates **shared** tooling from **KMS-only** helpers so node-image and KMS release lanes can evolve independently.

| Path | Purpose |
|------|---------|
| **`shared/`** | Dual-shape attest JSON (merod `data.quoteB64` and mero-kms `/attest` top-level `quoteB64`): Intel Trust Authority verification (`verify_tdx_quote_ita.py`) and policy candidate extraction (`extract_tdx_policy_candidates.py`). Used by **both** node-image-gcp and KMS Phala workflows. |
| **`kms/`** | Phala/dstack-specific checks: compose hash from event log (`verify_dstack_compose_hash.py`). |

**Node-image release automation** (GCP image, published MRTDs, signatures) lives under `scripts/release/node-image-gcp/`, not here.

**KMS Phala deployment** (compose template, `provision_prod.py`) lives under `scripts/kms/phala/`.
