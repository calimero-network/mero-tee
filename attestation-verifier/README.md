# Calimero Attestation Verifier

A public, open-source web tool to verify Phala KMS and mero-tee node attestations against official release policy. Supports ITA (Intel Trust Authority) quote verification via backend.

## Deploy on Vercel

1. **Connect repo** to Vercel (or deploy from `attestation-verifier/` as root directory).
2. **Add env vars**:
   - `ITA_API_KEY` — Intel Trust Authority API key
3. **Deploy**. No Redis or other storage required.

## Usage

### From MDMA

1. Open a KMS deployment (with KMS URL set) → Attestation section.
2. Click **"Verify in verifier"** — opens the verifier in a new tab with ITA verification + compose_hash comparison.

### KMS verification (paste or fetch)

1. Open the verifier URL (optionally with `?kms_url=...`).
2. Enter KMS URL and click "Fetch attestation", or paste attestation JSON.
3. Click "Verify KMS".

### Node verification

1. Open the **Mero TEE Verification** tab.
2. Enter node URL (for example `http://<public-ip>:80`).
3. Optionally set a release tag (`mero-tee-vX.Y.Z`) to compare against a specific published policy.
4. Click **Verify node**.

### Flow

1. Client opens verifier with `?kms_url=...` (or enters KMS URL and triggers verify).
2. Frontend POSTs `{ kms_url }` to `/api/verify`.
3. Backend fetches attestation from KMS `/attest`, calls ITA with the quote.
4. Backend returns `{ attestation, ita_response, ita_token }` in the same response.
5. Page displays ITA verification + compose_hash match. No storage required.

## What it does

- **ITA verification**: Quote verified by Intel Trust Authority; signed token returned for client verification.
- **Compose hash**: Extracted from event log, compared with `kms-phala-compatibility-map.json`.
- **Policy match**: Shows which profile (debug, debug-read-only, locked-read-only) matches.

## Security

- **SSRF protection**: `kms_url` restricted to HTTPS and allowed hosts (default: `*.phala.network`, localhost). Override with `KMS_ALLOWED_HOSTS`.
- **Node URL allowlist**: `node_url` is restricted to allowed host regexes (default allows IPv4 + localhost). Override with `NODE_ALLOWED_HOSTS`.
- **Nonce verification**: For `kms_url` flow, backend verifies `reportDataHex[0..32]` matches the nonce sent to KMS (prevents replay). Node flow performs the same check when report-data fields are present.
- **Client-side JWT verification**: Token signature verified against Intel JWKS (`portal.trustauthority.intel.com/certs`) before display.
- **No secrets in logs**: verifier utility code avoids unconditional debug logging of event payloads.

## Operations runbook

For operational guidance (key rotation, incident response, and deployment checks), see:

- `docs/runbooks/platforms/attestation-verifier.md`
