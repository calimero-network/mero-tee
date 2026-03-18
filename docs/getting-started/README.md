# Getting Started

Start here if you are deploying, operating, or verifying `mero-tee` assets.

## Pick your lane first

`mero-tee` has two non-symmetric operational lanes:

1. **Phala lane (KMS plane)**: operate `mero-kms-phala`
2. **GCP lane (node image plane)**: deploy locked `node-image-gcp` artifacts

Use the lane-specific runbooks:

- [Phala KMS lane](../runbooks/platforms/phala-kms.md)
- [GCP node lane](../runbooks/platforms/gcp-merod.md)

## First-time operator checklist

1. Read [Trust and verification](../release/trust-and-verification.md)
2. Verify release assets before deployment
3. Apply release-pinned attestation policy
4. Follow lane-specific rollout guidance

## Related references

- [Platform runbooks index](../runbooks/platforms/README.md)
- [Architecture graph](../DOCS_GRAPH.md)
- [Diagrams hub](../diagrams/README.md)
