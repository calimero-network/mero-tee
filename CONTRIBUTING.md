# Contributing to mero-tee

Thanks for your interest in contributing.

## Scope

This repository contains TEE infrastructure for Calimero, including:

- `mero-kms` (the KMS service, root Rust package, run as a GCP TDX cluster image)
- `node-image-gcp` (locked image build pipeline, for the node and KMS images)
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
- `gcloud`, Packer and Ansible (for image builds and probe workflows)

### Build

```bash
cargo build --release
```

### Basic checks

```bash
cargo check
cargo test
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

- `.github/workflows/release-kms.yaml`
- `.github/workflows/release-node-image-gcp.yaml`
- `.github/workflows/kms-tdx-image-probe.yaml`
- `mero-tee/playbook-kms.yml` and `mero-tee/ansible/roles/mero-kms/`
- `scripts/policy/*.sh`

please include a brief risk assessment in the PR description.
