# mero-kms-phala policy records

This directory stores versioned KMS attestation policy records proposed from
staging probe runs and promoted via pull requests.

- `index.json` tracks available policy files by release tag.
- `<tag>.json` files (for example `1.2.3.json`) contain machine-readable policy
  values and provenance metadata.

These files are the reviewable governance layer between:

1. **probe evidence collection** (`kms_staging_probe_phala.yaml`), and
2. **release publication/signing** (`release-mero-kms-phala.yaml`).
