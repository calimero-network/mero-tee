# Contributing to mero-tee

Thanks for your interest in contributing.

## Scope

This repository contains TEE infrastructure for Calimero, including:

- `mero-kms-phala` (Phala KMS service, root Rust package)
- `node-image-gcp` (locked image build pipeline)
- release verification scripts and workflows

## Development setup

### Prerequisites

- Rust toolchain (stable)
- `cargo`
- `jq`
- `bash`
- Node.js 20+ and `npm` (for `attestation-verifier`)

Some workflows/scripts also rely on:

- `gh` (GitHub CLI)
- `cosign` (for signature verification workflows)
- `phala` CLI (for staging probe workflows)

### Build

```bash
cargo build --release
```

### Basic checks

```bash
cargo check
cargo fmt --all --check
cargo clippy -p mero-kms-phala --all-targets -- -D warnings
cargo test
```

Verifier checks:

```bash
cd attestation-verifier
npm ci
npm run lint
npm run test
npm run build
```

## Pull requests

1. Keep PRs focused and small where possible.
2. Include a clear description of:
   - what changed
   - why it changed
   - operational/security impact
3. Update docs when behavior, workflows, or operator procedures change.
4. Add or update tests when feasible.
5. Never commit secrets or credentials.

## Commit style

Conventional-style commit prefixes are preferred (for example `fix:`, `feat:`, `docs:`, `chore:`).

## Security and secrets

- Do **not** commit API keys, private keys, `.env` secrets, or cloud credentials.
- Review [SECURITY.md](SECURITY.md) before opening a PR.
- For vulnerabilities, follow the reporting process in `SECURITY.md` instead of filing a public issue.

## Release/process notes

Release and attestation workflows are security-sensitive. If you modify:

- `.github/workflows/release-kms-phala.yaml`
- `.github/workflows/release-node-image-gcp.yaml`
- `.github/workflows/kms-phala-staging-probe.yaml`
- `scripts/policy/*.sh`

please include a brief risk assessment in the PR description.
