# Release verification output examples

This page provides expected output patterns for release verification scripts.

Use these examples to quickly identify successful verification vs common failure modes.

## KMS release asset verification

Script:

```bash
scripts/release/verify-kms-phala-release-assets.sh X.Y.Z
```

The KMS release workflow also publishes a signed convenience archive:
`kms-phala-trust-bundle.tar.gz` (+ `.sig` / `.pem`), which packages
checksums, release manifest, and attestation policy.

It also publishes `kms-phala-rekor-index.json`, which records Rekor
metadata for each signed asset (`log_index`, `integrated_time`, `log_id`).
`log_id` is read from Sigstore bundle JSON at
`.verificationMaterial.tlogEntries[0].logId.keyId` (protobuf JSON camelCase).
Each index entry also includes `hash` and `sigstore_search_url`, so operators
can directly open public transparency search pages such as
`https://search.sigstore.dev/?hash=sha256:<artifact-hash>`.

Additionally, `kms-phala-container-metadata.json` is published and signed
as a standalone container metadata artifact and cross-checked by the verifier.

### Expected success output

```text
Inspecting kms-phala release X.Y.Z...
Release X.Y.Z checksums, manifest, attestation policy, container metadata, archive hashes, and Sigstore signatures verified.
```

### Common failure patterns

- Missing release asset:

```text
Failed to download required asset kms-phala-release-manifest.json
```

- Hash mismatch:

```text
Checksum mismatch between manifest and checksums for mero-kms-phala_x86_64-unknown-linux-gnu.tar.gz
```

- Signature/identity mismatch:

```text
Error: no matching signatures:
```

## node-image-gcp release asset verification

Script:

```bash
scripts/release/verify-node-image-gcp-release-assets.sh X.Y.Z
```

### Expected success output

```text
Inspecting release X.Y.Z...
Release X.Y.Z asset set, provenance checks, and Sigstore signature verification passed.
```

### Common failure patterns

- Missing checksums entry:

```text
Checksums file missing entry for release-provenance.json
```

- Invalid provenance structure:

```text
jq: error (at .../release-provenance.json): ...
```

- Signature/identity mismatch:

```text
Error: no matching signatures:
```

## Operator troubleshooting checklist

If verification fails:

1. Confirm release tag exists and is correct.
2. Confirm required release assets (`.json`, `.sig`, `.pem`) are present.
3. Confirm your `COSIGN_CERTIFICATE_IDENTITY_REGEXP` was not overridden incorrectly.
4. Retry after a short delay if release assets are still being uploaded.
5. Treat repeated signature failures as release-blocking and escalate.
