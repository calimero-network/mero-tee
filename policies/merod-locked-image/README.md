# merod locked-image policy records

This directory stores versioned, reviewable measurement policy records for
GCP locked merod images.

- `index.json` tracks available policy files by release tag and stores historical
  metadata (`policy_id`, `status`, `policy_sha256`).
- `<tag>.json` files (for example `2.1.4.json`) contain profile-specific
  measurement allowlists used for attestation verification:
  - `allowed_mrtd`
  - optional `allowed_rtmr0..3`
  - optional `allowed_tcb_statuses`

These files provide the governance layer between:

1. **GCP locked image build + attestation evidence** (`gcp_locked_image_build.yaml`), and
2. **release trust artifacts** (`published-mrtds.json`, `merod-locked-image-policy.json`).
