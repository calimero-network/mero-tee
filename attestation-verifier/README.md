# Attestation Verifier

Public web tool for verifying KMS and node attestations via Intel Trust Authority (ITA).

> **Full documentation**: [Components — Attestation Verifier](https://calimero-network.github.io/mero-tee/components.html)

## Deploy

Vercel with environment variables: `ITA_API_KEY`, `ITA_APPRAISAL_URL`, `KMS_ALLOWED_HOSTS`, `NODE_ALLOWED_HOSTS`.

## Flow

1. User provides KMS URL or pastes attestation
2. API fetches `/attest` from KMS
3. Quote sent to ITA for verification
4. Nonce binding and JWT verification
5. Results displayed with measurement comparison

## Development

```bash
cd attestation-verifier
npm install
npm run dev
```
