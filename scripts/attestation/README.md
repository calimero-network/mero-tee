# Attestation scripts

Shared tooling for verifying TDX quotes and turning them into measurement allowlists. The node-image and KMS release lanes both use it.

| Path | Purpose |
|------|---------|
| **`shared/`** | Dual-shape attest JSON (merod `data.quoteB64` and mero-kms `/attest` top-level `quoteB64`): Intel Trust Authority verification (`verify_tdx_quote_ita.py`) and policy candidate extraction (`extract_tdx_policy_candidates.py`). Used by **both** the node-image-gcp and the mero-kms (GCP TDX) release workflows. |
| **`shared/tdx_event_log.py`** | Lists, replays and diffs a TD's CCEL event log against a quote's RTMRs. |
| **`shared/uki_probe_evidence.py`** | Reads the UKI TDX probe's evidence off its serial console and checks the firmware measured the UKI the build produced, by Authenticode SHA-384 ([`uki-tdx-probe.yaml`](../../.github/workflows/uki-tdx-probe.yaml)). |
| **`shared/compute_rtmr.py`** | Computes a UKI image's RTMR1 and RTMR2 from its disk image and UKI, before boot, and compares them event by event with a booted TD's log and quote. |

**Node-image release automation** (GCP image, published MRTDs, signatures) lives under `scripts/release/node-image-gcp/`, not here.

**KMS release automation** (two-replica cluster probe on the built KMS image, policy assembly, signatures) lives under `scripts/release/kms/`.
