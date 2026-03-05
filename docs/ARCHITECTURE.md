# Architecture & verification boundaries

This document describes **who does what** in attestation and release trust.

The key design rule is to separate:

- **artifact trust** (release signing/checksums/policy metadata), and
- **runtime trust** (quote verification + policy enforcement at runtime).

---

## Repository boundaries

`mero-tee` and `core` are separate repositories with different responsibilities.

| Repository | Owns | Does not own |
|---|---|---|
| `calimero-network/mero-tee` | KMS implementation (`mero-kms-phala`), GCP locked-image build/release assets, policy registry + release verification scripts | `merod` runtime logic |
| `calimero-network/core` | `merod` runtime behavior, KMS client flow, node-side attestation configuration handling | KMS release packaging and locked-image release assets from `mero-tee` |

Implementation references:

- `mero-tee`: `crates/mero-kms-phala/src/handlers.rs`
- `core`: `crates/merod/src/kms.rs`

---

## Platform lanes (not symmetric deployments)

The repo contains two lanes that are related but different:

1. **Phala lane (KMS plane)**  
   Deploy and operate `mero-kms-phala`; `merod` talks to KMS for key release.
2. **GCP lane (node image plane)**  
   Build/verify/deploy locked `merod` images and validate measurements.

Runbooks:

- [Phala KMS lane](platforms/phala-kms.md)
- [GCP locked-image lane](platforms/gcp-merod.md)

---

## Attestation enforcement points

### A) `merod` verifies KMS before key fetch (in `core`)

When enabled, `merod`:

1. Calls KMS `POST /attest`
2. Verifies quote cryptographically
3. Verifies nonce/binding in report data
4. Enforces KMS measurement policy (MRTD/RTMR + TCB)
5. Only then executes `/challenge` + `/get-key`

Source: `core/crates/merod/src/kms.rs` (`verify_kms_attestation`, `fetch_from_phala`)

### B) KMS verifies node before key release (in `mero-tee`)

`mero-kms-phala`:

1. Issues one-time challenge
2. Verifies peer identity + signature
3. Verifies quote validity and report-data layout
4. Enforces measurement policy allowlists
5. Derives/releases key

Source: `crates/mero-kms-phala/src/handlers.rs` (`get_key_handler`, policy enforcement)

---

## Release trust model

`mero-tee` publishes two release asset families:

1. KMS assets on `X.Y.Z`
2. Locked-image assets on `locked-image-vX.Y.Z`

For each family, signatures prove workflow identity/integrity, but not complete
runtime safety by themselves.

Use:

- `scripts/verify-kms-phala-release-assets.sh`
- `scripts/verify-node-image-gcp-release-assets.sh`
- `scripts/verify-release-assets.sh`

Then enforce runtime attestation in deployed services.

---

## What is guaranteed, and where

| Guarantee | Enforced by | Where |
|---|---|---|
| Release artifact integrity + provenance | Sigstore verification scripts | operator CI/acceptance |
| KMS quote validity + KMS measurement policy | `merod` KMS client logic | node startup/runtime |
| Node quote validity + node measurement policy | `mero-kms-phala` | key release path |
| Full infra/control-plane safety | Not fully covered by attestation | requires ops controls |

---

## Operator workflow (high-level)

1. Verify signed release assets.
2. Pin release and digests.
3. Apply release-pinned attestation policy config.
4. Roll out by platform lane.
5. Verify runtime measurements/quotes in production.

See:

- [Trust & verification](TRUST_AND_VERIFICATION.md)
- [TEE verification for beginners](TEE_VERIFICATION_FOR_BEGINNERS.md)
- [Verify MRTD](verify-mrtd.md)
