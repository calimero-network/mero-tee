# Deploy merod on Phala Network (TEE)

This guide covers deploying merod nodes on Phala Cloud's TEE infrastructure using dstack. merod runs inside a Confidential VM (CVM) and uses the Phala KMS to obtain its storage encryption key at startup.

## Overview

When merod runs in TEE mode on Phala:

1. **merod** – From [calimero-network/core](https://github.com/calimero-network/core) releases
2. **mero-kms-phala** – KMS that validates attestation and releases the key. Must run in the same CVM.
3. **dstack** – Phala's TEE runtime; KMS uses it for attestation and key derivation.

## Prerequisites

- [Phala Cloud account](https://cloud.phala.com/register)
- Docker Compose for your deployment
- Understanding of [dstack](https://docs.phala.network/dstack/overview) and [Phala Cloud CVM](https://docs.phala.network/phala-cloud/cvm/create-with-docker-compose)

## Building mero-kms-phala

From this repository:

```bash
git clone https://github.com/calimero-network/mero-tee.git
cd mero-tee
cargo build --release -p mero-kms-phala
# Binary: target/release/mero-kms-phala
```

Or use the prebuilt container from [mero-tee releases](https://github.com/calimero-network/mero-tee/releases):

```bash
docker pull ghcr.io/calimero-network/mero-kms-phala:<version>
```

## Docker Compose for Phala CVM

All services run in the same CVM. Example:

```yaml
services:
  mero-kms:
    image: ghcr.io/calimero-network/mero-kms-phala:2.1.3
    ports:
      - "8080:8080"
    environment:
      LISTEN_ADDR: "0.0.0.0:8080"
      DSTACK_SOCKET_PATH: "/var/run/dstack.sock"
      CHALLENGE_TTL_SECS: "60"
      ACCEPT_MOCK_ATTESTATION: "false"
      ENFORCE_MEASUREMENT_POLICY: "true"
      ALLOWED_TCB_STATUSES: "UpToDate"
      # Pin measurements for production (see crates/mero-kms-phala/README.md)
      # ALLOWED_MRTD: "<hex>"
      # ALLOWED_RTMR0: "<hex>"
      # ...
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock

  merod:
    image: ghcr.io/calimero-network/merod:2.1.3
    ports:
      - "2428:2428"
      - "2528:2528"
    environment:
      CALIMERO_HOME: "/data"
    volumes:
      - merod-data:/data
    depends_on:
      - mero-kms
```

**Important:** KMS must start before merod so the key can be fetched at startup.
Use pinned tags or digests for production; avoid mutable tags such as `:latest`.

## Deploying to Phala Cloud

1. **Create a Phala Cloud account** at [cloud.phala.com](https://cloud.phala.com/register).

2. **Prepare your Docker Compose** with merod and mero-kms-phala as above.

3. **Deploy via Phala Cloud UI:**
   - Go to the deployment section
   - Switch to the Advanced tab
   - Paste or upload your `docker-compose.yml`
   - Deploy

4. **Or use Phala Cloud CLI** (see [Start from Cloud CLI](https://docs.phala.network/phala-cloud/phala-cloud-cli/start-from-cloud-cli)).

5. **Verify attestation** – Use the [TEE Attestation Explorer](https://ra-quote-explorer.vercel.app/).

## Setting Up merod for TEE

### 1. Initialize the node

```bash
merod --home /data --node default init \
  --server-port 2428 \
  --swarm-port 2528 \
  --boot-network calimero-dev
```

### 2. Add TEE/KMS configuration

```bash
merod --home /data --node default config \
  'tee.kms.phala.url="http://mero-kms:8080/"'
```

For production, apply release-pinned attestation policy from signed artifacts:

```bash
scripts/apply_merod_kms_attestation_config.sh 2.1.3 http://mero-kms:8080/ /data default
```

### 3. Run merod

```bash
merod --home /data --node default run
```

## Production: Pinning MRTD/RTMR

For production, pin the measurements of your deployed image. See [mero-kms-phala README](../crates/mero-kms-phala/README.md) for full KMS configuration.

## Development Mode

For local testing without TDX hardware, set `ACCEPT_MOCK_ATTESTATION=true` on the KMS. **Do not use in production.**

## See Also

- [mero-kms-phala README](../crates/mero-kms-phala/README.md) – KMS endpoints and policy
- [core tee-mode](https://github.com/calimero-network/core/blob/master/docs/tee-mode.md) – merod TEE config
- [Phala Cloud Documentation](https://docs.phala.network/)
- [dstack Overview](https://docs.phala.network/dstack/overview)
