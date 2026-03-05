# mero-kms-phala policy records

This directory stores versioned KMS attestation policy records proposed from
staging probe runs and promoted via pull requests.

- `<tag>.json` files (for example `1.2.3.json`) contain machine-readable policy
  values and provenance metadata.
- `policies/index.json` (at the parent directory level) maps each release
  version to the corresponding KMS and merod policy tags/paths.

Release automation reads this registry for the target crate version, so each
published release is tied to a reviewed policy record for the same tag.

These files are the reviewable governance layer between:

1. **probe evidence collection** (`kms_staging_probe_phala.yaml`), and
2. **release publication/signing** (`release-mero-kms-phala.yaml`).
