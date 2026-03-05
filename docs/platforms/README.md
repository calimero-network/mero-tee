# Platform runbooks

This section is organized by **deployment target and responsibility**, not by a
generic "deploy X on Y" pattern.

## Why this structure exists

`mero-tee` has two different operational lanes:

1. **Phala lane (KMS plane)**  
   You deploy and operate `mero-kms-phala` (attestation + key release service).
2. **GCP lane (node image plane)**  
   You consume/deploy locked `merod` images and verify published measurements.

These are related but not symmetric. Treating them as two equivalent deployment
guides causes confusion.

## Runbooks

- [Phala: deploy and operate `mero-kms-phala` (KMS plane)](phala-kms.md)
- [GCP: deploy `merod` locked images (node plane)](gcp-merod.md)

## Related cross-cutting docs

- [Architecture & verification boundaries](../ARCHITECTURE.md)
- [Trust & verification entry point](../TRUST_AND_VERIFICATION.md)
- [TEE verification for beginners](../TEE_VERIFICATION_FOR_BEGINNERS.md)
