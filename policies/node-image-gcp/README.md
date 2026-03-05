# merod locked-image policy records

This directory stores versioned, reviewable measurement policy records for
GCP locked merod images.

- `<tag>.json` files (for example `2.1.4.json`) contain profile-specific
  measurement allowlists used for attestation verification:
  - `allowed_mrtd`
  - optional `allowed_rtmr0..3`
  - optional `allowed_tcb_statuses`
- `policies/index.json` (at the parent directory level) maps each release
  version to the corresponding KMS and merod policy tags/paths.

These files provide the governance layer between:

1. **GCP locked image build + attestation evidence** (`release-node-image-gcp.yaml`), and
2. **release trust artifacts** (`published-mrtds.json`, `merod-locked-image-policy.json`).
