# Attestation Verifier

Public web tool for verifying KMS and node attestations via Intel Trust Authority (ITA).

> **Full documentation**: [Components — Attestation Verifier](https://calimero-network.github.io/mero-tee/components.html)

## Deploy

Vercel with environment variables: `ITA_API_KEY`, `ITA_APPRAISAL_URL`, `NODE_ALLOWED_HOSTS`.

## Flow

1. Node: the user gives a node URL and the API fetches `/admin-api/tee/attest` with a fresh nonce.
   KMS: mero-kms replicas are reachable only inside their VPC, so the operator calls a replica's
   `/attest` there and pastes the response (optionally with the nonce they sent).
2. Quote sent to ITA for verification
3. Nonce binding and JWT verification
4. MRTD/RTMR0-3 compared with the release policy: `kms-attestation-policy.<profile>.json`
   (KMS allowlists) or `published-mrtds.json` (nodes)

## Development

```bash
cd attestation-verifier
npm install
npm run dev
```
