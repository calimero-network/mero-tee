# Attestation verifier runbook

This runbook covers operating the public `attestation-verifier` service.

## Scope

- Frontend + API routes under `attestation-verifier/`
- ITA integration via `ITA_API_KEY`
- URL allowlisting for KMS/node verification requests

## Required secrets and env vars

- `ITA_API_KEY` (required): Intel Trust Authority API key used by `api/verify`.
- `KMS_ALLOWED_HOSTS` (optional): comma-separated host regexes for KMS URL validation.
- `NODE_ALLOWED_HOSTS` (optional): comma-separated host regexes for node URL validation.

## Secret rotation

1. Create a new ITA API key in Intel Trust Authority.
2. Update `ITA_API_KEY` in the deployment environment.
3. Redeploy verifier.
4. Validate with one KMS and one node verification request.
5. Revoke the old ITA key.

## Operational checks

- Health check: open verifier page and run one KMS verification.
- API behavior: ensure `/api/verify` returns attestation + ITA fields.
- Policy fetch behavior: verify `/api/policy`, `/api/node-policy`, and `/api/compat-map` work for current release tags.

## Incident response (high level)

### Suspected secret leak

1. Rotate `ITA_API_KEY` immediately.
2. Review deployment logs for unusual spikes/errors.
3. Audit recent changes in `attestation-verifier/api/*`.

### Suspected SSRF abuse

1. Restrict `KMS_ALLOWED_HOSTS` and `NODE_ALLOWED_HOSTS` to approved hosts.
2. Redeploy.
3. Review logs/metrics for repeated denied hosts and high-frequency failed requests.

### Broken verification after release

1. Confirm target release assets exist in GitHub releases.
2. Verify `release_tag` correctness (`mero-kms-vX.Y.Z` or `mero-tee-vX.Y.Z`).
3. Compare measurements with published release policy assets.
4. If needed, pin verification to a known-good release tag until issue is resolved.
