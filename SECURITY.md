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

- `published-mrtds.json`, `release-provenance.json`, and `attestation-artifacts.tar.gz` are shipped with Sigstore signatures (`.sig`) and certificates (`.pem`).
- Users verify MRTDs before trusting deployed nodes.
- See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the trust model.
