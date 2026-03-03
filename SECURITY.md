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
- **Release signing**: GPG private key stays in secure storage; only public key (`RELEASE_KEY.asc`) may be committed.
- **Packer vars**: Use `vars.GCP_*` in workflows; sensitive values go in GitHub repo variables/secrets.
- **Ansible**: No hardcoded secrets. Use `metrics-secret-name` / `logs-secret-name` metadata (GCP Secret Manager) for observability.

## Verification

- `published-mrtds.json` and attestation artifacts are signed (when signing is enabled).
- Users verify MRTDs before trusting deployed nodes.
- See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the trust model.
