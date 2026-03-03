# Deploy merod on GCP (TEE)

This guide covers deploying merod nodes on GCP TDX Confidential VMs using locked images built by mero-tee.

## Overview

merod runs in a TDX Confidential VM with:

1. **merod** – From [calimero-network/core](https://github.com/calimero-network/core) releases
2. **Locked image** – Packer-built image from mero-tee with attestation and MRTDs
3. **TEE storage** – Datastore encrypted with keys derived from attestation

## Prerequisites

- GCP project with TDX-capable VMs (e.g. `c3-standard-4` in supported regions)
- Access to mero-tee releases for `published-mrtds.json` and image references

## Locked Images

mero-tee builds locked merod node images via Packer. The workflow publishes:

- `published-mrtds.json` – Trusted measurements for verification
- `mrtd-*.json` – Per-profile MRTD values
- Attestation artifacts and provenance

See [packer/gcp/merod/README.md](../packer/gcp/merod/README.md) for build details.

### Profiles

- **debug** – Full merod, no lockdown
- **debug-read-only** – Read-only merod, no lockdown
- **locked-read-only** – Read-only merod with lockdown (production)

## Deployment Options

### Option 1: Use Pre-built Images

1. Fetch the latest release from [mero-tee releases](https://github.com/calimero-network/mero-tee/releases)
2. Download `published-mrtds.json` for verification
3. Use the GCP image built by the workflow (configure manually or via your provisioning tool)
4. Configure merod for TEE (see [core tee-mode docs](https://github.com/calimero-network/core/blob/master/docs/tee-mode.md))

### Option 2: Build Locally

```bash
cd packer/gcp/merod
packer build -var-file=ubuntu-intel.pkrvars.hcl ubuntu.pkr.hcl
```

Requires Packer, Ansible, and GCP credentials. See [packer/gcp/merod/README.md](../packer/gcp/merod/README.md).

## merod Configuration

For TEE mode on GCP, merod uses the storage key derived from attestation. No separate KMS is required (unlike Phala); the key is derived from the TDX runtime.

Configure merod as per [core tee-mode.md](https://github.com/calimero-network/core/blob/master/docs/tee-mode.md). GCP TDX nodes use the built-in attestation path.

## Verification

Use `published-mrtds.json` to verify deployed nodes match the expected image. See [Verify MRTD](verify-mrtd.md) for step-by-step instructions (curl commands, comparison script, and full quote verification).

## See Also

- [packer/gcp/merod/README.md](../packer/gcp/merod/README.md) – Image build
- [core tee-mode](https://github.com/calimero-network/core/blob/master/docs/tee-mode.md) – merod TEE config
- [verify-mrtd.md](verify-mrtd.md) – Verify nodes run the attested image
- [ARCHITECTURE.md](ARCHITECTURE.md) – Verification flow
