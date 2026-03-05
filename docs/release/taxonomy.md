# Release taxonomy

This document defines release classes used for `mero-tee` artifacts.

## Release classes

### Stable release (`X.Y.Z`)

Use for production-ready releases.

Requirements:

- Full CI/release workflow passes.
- Signed release assets are published and verifiable.
- Policy registry mapping exists for the same version.
- Operator docs are up to date.

### Release candidate (`X.Y.Z-rcN`)

Use for pre-production validation.

Requirements:

- Release workflow passes and assets are signed.
- Tagged as non-final in release notes.
- Migration/rollback expectations documented.

### Hotfix (`X.Y.Z+hotfixN` or incremented patch)

Use for urgent, narrowly scoped production fixes.

Requirements:

- Scope is explicitly documented in release notes.
- Verification scripts pass against the published tag.
- Follow-up issue/PR for broader remediation is linked.

## Operational rules

1. Never use mutable deployment tags (for example `:latest`) in production.
2. Prefer digest-pinned image references in deployment manifests.
3. Every release class must preserve signed trust artifacts and verification paths.
4. Policy and release versions should remain aligned through `policies/index.json`.

## Release note minimum content

Each release note should include:

- Version and commit SHA
- Digest/checksum references
- Verification command snippets
- Rollout/rollback guidance for operators
