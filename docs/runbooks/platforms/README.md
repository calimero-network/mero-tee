# Platform runbooks

This section is organized by **deployment target and responsibility**, not by a
generic "deploy X on Y" pattern.

## Why this structure exists

`mero-tee` has two different operational lanes:

1. **Mero KMS TEE lane**  
   You deploy and operate `mero-kms-phala` (attestation + key release service).
2. **Mero Node TEE lane**  
   You consume/deploy `node-image-gcp` artifacts and verify published measurements.

These are related but not symmetric. Treating them as two equivalent deployment
guides causes confusion.

## Runbooks

- [Mero KMS TEE: deploy and operate `mero-kms-phala`](phala-kms.md)
- [Mero Node TEE: deploy `merod` node-image artifacts](gcp-merod.md)

## Related cross-cutting docs

- [Architecture & verification boundaries](../../architecture/trust-boundaries.md)
- [Trust & verification entry point](../../release/trust-and-verification.md)
