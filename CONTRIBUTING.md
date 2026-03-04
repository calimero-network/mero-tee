# Contributing to mero-tee

Thanks for your interest in contributing.

## Scope

This repository contains TEE infrastructure for Calimero, including:

- `crates/mero-kms-phala` (Phala KMS service)
- `packer/gcp/merod` (locked image build pipeline)
- release verification scripts and workflows

## Development setup

### Prerequisites

- Rust toolchain (stable)
- `cargo`
- `jq`
- `bash`

Some workflows/scripts also rely on:

- `gh` (GitHub CLI)
- `cosign` (for signature verification workflows)
- `phala` CLI (for staging probe workflows)

### Build

```bash
cargo build --release -p mero-kms-phala
```

### Basic checks

```bash
cargo check -p mero-kms-phala
cargo test -p mero-kms-phala
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

- `.github/workflows/release-mero-kms-phala.yaml`
- `.github/workflows/gcp_locked_image_build.yaml`
- `.github/workflows/kms_staging_probe_phala.yaml`
- `.github/workflows/kms_policy_promotion_pr.yaml`

please include a brief risk assessment in the PR description.
