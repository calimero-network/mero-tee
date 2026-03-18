# Project Boundaries

Each major top-level folder in this repository is treated as a separate project area with a distinct responsibility.

## Project map

| Project area | Scope | Primary docs |
|---|---|---|
| Repository root (`/`) | Cross-project trust model, release coordination, shared documentation entrypoints | [README.md](../../README.md), [docs/README.md](../README.md) |
| `mero-kms/` | `mero-kms-phala` implementation and runtime behavior | [mero-kms/README.md](../../mero-kms/README.md) |
| `mero-tee/` | Mero Node TEE image build/deploy automation and artifacts (`node-image-gcp`) | [mero-tee/README.md](../../mero-tee/README.md) |
| `attestation-verifier/` | Verification web UI and API helpers | [attestation-verifier/README.md](../../attestation-verifier/README.md) |

## Boundary rules

- Keep component internals in that component's own README/docs.
- Keep root docs focused on cross-project architecture and operational integration.
- Cross-link instead of duplicating component-specific procedures.
