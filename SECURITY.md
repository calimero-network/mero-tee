# Security

## No Secrets in This Repository

**Never commit:**

- Private keys (`.pem`, `.key`, `*-key.json`)
- GCP service account keys
- GitHub tokens or API keys
- Passwords or credentials
- `.env` files with secrets

## Safe Patterns

- **GCP credentials**: Use GitHub Actions secrets (`GCP_SERVICE_ACCOUNT_KEY`, `GCP_WORKLOAD_IDENTITY_*`) or environment variables at runtime. Never store in repo.
- **Release signing**: Locked-image release assets are keyless-signed with Sigstore (GitHub OIDC identity). No signing private key is stored in this repository.
- **Packer vars**: Use `vars.GCP_*` in workflows; sensitive values go in GitHub repo variables/secrets.
- **Ansible**: No hardcoded secrets. Use `metrics-secret-name` / `logs-secret-name` metadata (GCP Secret Manager) for observability.

## Verification

- `published-mrtds.json` and `release-provenance.json` are shipped with Sigstore signatures (`.sig`) and certificates (`.pem`).
- Users verify MRTDs before trusting deployed nodes.
- See [docs/architecture/trust-boundaries.md](docs/architecture/trust-boundaries.md) for the trust model.

## Reporting Vulnerabilities

Please do **not** open public GitHub issues for suspected vulnerabilities.

- Contact: info@calimero.network
- Include:
  - affected component/path
  - reproduction steps or proof-of-concept
  - potential impact
  - proposed mitigations (if any)

We will acknowledge receipt and triage as quickly as possible.

## Supported Versions

Security fixes are generally applied to the latest `master` branch and latest
released version stream.
