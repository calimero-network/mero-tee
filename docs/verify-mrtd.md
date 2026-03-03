# Verify MRTD: Is the Node Running the Claimed Image?

This guide explains how end users and operators verify that a GCP TDX merod node is running the expected locked image. A matching MRTD (Measurement Root of Trust for Delivery) proves the node booted from the attested image.

## Verify signed release assets first (Sigstore keyless)

Before trusting `published-mrtds.json`, verify the release assets were signed by this repository's release workflow identity.

```bash
VERSION="2.1.1"
REPO="calimero-network/mero-tee"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

# Install cosign if needed: https://docs.sigstore.dev/cosign/system_config/installation/
curl -sSLO "${BASE_URL}/published-mrtds.json"
curl -sSLO "${BASE_URL}/published-mrtds.json.sig"
curl -sSLO "${BASE_URL}/published-mrtds.json.pem"

cosign verify-blob \
  --certificate published-mrtds.json.pem \
  --signature published-mrtds.json.sig \
  --certificate-identity-regexp "^https://github.com/${REPO}/.github/workflows/gcp_locked_image_build.yaml@refs/heads/master$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  published-mrtds.json
```

For full provenance validation, verify `release-provenance.json` and `attestation-artifacts.tar.gz` the same way using their matching `.sig` and `.pem` files.

## Quick verification (MRTD comparison)

### 1. Get the node's MRTD

Query the node's admin API (replace `<node-ip>` with the node's IP or hostname, and ensure port 80 or your admin port is reachable):

```bash
curl -s https://<node-ip>/admin-api/tee/info | jq -r '.mrtd'
```

Or over HTTP if not using TLS:

```bash
curl -s http://<node-ip>/admin-api/tee/info | jq -r '.mrtd'
```

The response also includes `cloudProvider`, `osImage`, and `profile`. Note the `profile` (e.g. `locked-read-only`) for the next step.

### 2. Fetch expected MRTDs from mero-tee releases

```bash
# Replace X.Y.Z with the release version (e.g. 2.1.1)
curl -sL https://github.com/calimero-network/mero-tee/releases/download/X.Y.Z/published-mrtds.json | jq
```

Extract the expected MRTD for your profile:

```bash
# For locked-read-only (production)
curl -sL https://github.com/calimero-network/mero-tee/releases/download/2.1.1/published-mrtds.json | jq -r '.profiles["locked-read-only"].mrtd'

# For debug
curl -sL https://github.com/calimero-network/mero-tee/releases/download/2.1.1/published-mrtds.json | jq -r '.profiles.debug.mrtd'

# For debug-read-only
curl -sL https://github.com/calimero-network/mero-tee/releases/download/2.1.1/published-mrtds.json | jq -r '.profiles["debug-read-only"].mrtd'
```

### 3. Compare

If the node's MRTD **matches** the expected MRTD for that profile, the node is running the attested locked image.

**Example script:**

```bash
#!/bin/bash
NODE_URL="${1:-http://localhost/admin-api}"
VERSION="${2:-2.1.1}"
PROFILE="${3:-locked-read-only}"

OBSERVED=$(curl -s "${NODE_URL}/tee/info" | jq -r '.mrtd')
EXPECTED=$(curl -sL "https://github.com/calimero-network/mero-tee/releases/download/${VERSION}/published-mrtds.json" | jq -r --arg p "$PROFILE" '.profiles[$p].mrtd')

if [[ -z "$OBSERVED" ]]; then
  echo "Error: Node did not report MRTD"
  exit 1
fi
if [[ -z "$EXPECTED" ]]; then
  echo "Error: Could not fetch expected MRTD for profile $PROFILE"
  exit 1
fi

if [[ "${OBSERVED,,}" == "${EXPECTED,,}" ]]; then
  echo "✓ MRTD match – node is running the attested image"
else
  echo "✗ MRTD mismatch – node may not be running the expected image"
  echo "  Observed: ${OBSERVED:0:64}…"
  echo "  Expected: ${EXPECTED:0:64}…"
  exit 1
fi
```

## Stronger verification (quote + Intel collateral)

For full cryptographic verification, verify the TDX quote and its certificate chain before trusting the MRTD:

1. **Request a quote** from the node with a fresh nonce:
   ```bash
   NONCE=$(openssl rand -hex 32)
   curl -s -X POST https://<node-ip>/admin-api/tee/attest \
     -H "Content-Type: application/json" \
     -d "{\"nonce\":\"$NONCE\"}" | jq
   ```

2. **Verify the quote** – Use Intel Trust Authority or the `calimero_tee_attestation` crate to:
   - Verify the quote signature and certificate chain against Intel PCS collateral
   - Check TCB status and policy compliance
   - Extract the MRTD from the verified quote

3. **Compare MRTD** – The MRTD from the verified quote must match the expected value in `published-mrtds.json` for the node's profile.

See [core tee-attestation](https://github.com/calimero-network/core/tree/master/crates/tee-attestation) for quote verification logic. MDMA and provisioning tools typically perform this verification automatically.

## What MRTD proves

| Verified by MRTD | Not in MRTD |
|------------------|-------------|
| OS (kernel, rootfs) | merod binary (downloaded at runtime from GitHub) |
| Lockdown (no SSH, no console) | Observability endpoints (from metadata) |
| Init service behavior | |
| Baked binaries (traefik, vmagent, vector) | |

A matching MRTD proves the node booted from the locked image. The merod binary is downloaded at runtime from [calimero-network/core](https://github.com/calimero-network/core) releases and is trusted separately.

## See Also

- [deploy-gcp.md](deploy-gcp.md) – Deployment overview
- [ARCHITECTURE.md](ARCHITECTURE.md) – Trust model and verification flow
- [core tee-mode](https://github.com/calimero-network/core/blob/master/docs/tee-mode.md) – merod TEE configuration
