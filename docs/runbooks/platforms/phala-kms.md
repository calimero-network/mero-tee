# Phala platform: deploy and operate `mero-kms-phala` (KMS plane)

This runbook is for operating the **KMS plane** on Phala CVMs.

It is **not** the GCP node-image-gcp deployment path.  
For GCP node-plane deployment, use [gcp-merod.md](gcp-merod.md).

---

## 1) Scope and responsibility

In the Phala lane:

- `mero-kms-phala` is the trust decision point for key release.
- `merod` (from `calimero-network/core`) proves node identity + attestation to KMS.
- KMS verifies quote validity, challenge freshness, peer binding, and policy
  allowlists before releasing storage keys.
- Production policy should require both quote verification and full measurement checks
  (MRTD + RTMR0..3) for both directions (`merod` verifying KMS and KMS verifying `merod`).

Implementation references:

- KMS verification and policy enforcement:
  - `mero-kms/src/handlers/get_key.rs`
  - `mero-kms/src/handlers/attest.rs`
- `merod` KMS client and KMS self-attestation verification:
  - `core/crates/merod/src/kms.rs`

---

## 2) Prerequisites

- Phala Cloud CVM environment with dstack socket available to KMS
- Docker/Compose deployment method for your CVM
- Signed release tag to pin (for example `2.1.10`)
- Tools for release verification: `bash`, `jq`, `curl`, `cosign` (and optional `gh`)

---

## 3) Verify release assets before deployment

Always verify signed assets before rollout:

```bash
TAG=2.1.10
scripts/release/verify-kms-phala-release-assets.sh "${TAG}"
```

This validates signatures, checksums, release manifest, attestation policy, and
container metadata consistency.

---

## 4) Deploy digest-pinned KMS image

Use digest pinning from `kms-phala-release-manifest.json`:

```bash
# Example only; fetch value from verified release manifest.
KMS_IMAGE="ghcr.io/calimero-network/mero-kms-phala@sha256:<digest>"
```

Minimal Compose skeleton (KMS + merod integration):

```yaml
services:
  mero-kms:
    image: ghcr.io/calimero-network/mero-kms-phala@sha256:<kms-image-digest>
    environment:
      LISTEN_ADDR: "0.0.0.0:8080"
      DSTACK_SOCKET_PATH: "/var/run/dstack.sock"
      CHALLENGE_TTL_SECS: "60"
      ACCEPT_MOCK_ATTESTATION: "false"
      ENFORCE_MEASUREMENT_POLICY: "true"
      MAX_PENDING_CHALLENGES: "10000"
      MERO_KMS_VERSION: "2.2.3"
      MERO_KMS_PROFILE: "locked-read-only"
      KEY_NAMESPACE_PREFIX: "merod/storage"
      # Optional: MERO_KMS_POLICY_SHA256 to verify fetched policy matches compatibility map
      # Optional HA/shared challenge store
      # REDIS_URL: "redis://redis:6379/0"
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
```

Production guidance:

- Keep `ACCEPT_MOCK_ATTESTATION=false`.
- Set `MERO_KMS_VERSION` and `MERO_KMS_PROFILE` for each deployment.
- Do not inject `USE_ENV_POLICY` or `ALLOWED_*` in standard release/probe flows.
- Do not use mutable container tags (`:latest`).
- Set `MERO_KMS_PROFILE=locked-read-only` for production cohorts.
- Keep KMS endpoints private to trusted network paths; do not expose key-release APIs publicly.
- Use TLS (preferably mTLS) on any non-local network path between `merod` and KMS.

---

## 5) Configure merod with release-pinned attestation policy

Use signed policy from the same reviewed release:

```bash
scripts/policy/apply-merod-kms-phala-attestation-config.sh --profile locked-read-only "${TAG}" http://mero-kms:8080/ /data default
```

This writes `tee.kms.phala.attestation.*` config values so `merod` verifies KMS
self-attestation (`/attest`) and enforces policy before key fetch.

---

## 6) Profile compatibility and trust cohorts

`node-image-gcp` publishes three profiles (`debug`, `debug-read-only`, `locked-read-only`), but production key-release policy should be treated as a separate trust cohort from debug/testing cohorts.

Recommended mapping:

| Node profile | KMS policy cohort | Keys |
|---|---|---|
| `debug` | dedicated debug/non-production KMS policy | non-production only |
| `debug-read-only` | dedicated pre-production KMS policy | non-production only |
| `locked-read-only` | production KMS policy | production keys |

Do not mix debug profile measurements into production KMS allowlists.
For release images, use profile-specific KMS tags (for example `vX.Y.Z-debug`, `vX.Y.Z-debug-read-only`, `vX.Y.Z-locked-read-only`).

---

## 7) Runtime checks

- KMS health:
  - `GET /health`
- KMS self-attestation endpoint:
  - `POST /attest`
- Key exchange endpoints:
  - `POST /challenge`
  - `POST /get-key`

The expected runtime sequence is documented in
[Architecture](../../architecture/trust-boundaries.md#attestation-enforcement-points).

Operational note for HA/LB deployments:

- `/challenge` state is in-memory by default; set `REDIS_URL` for shared challenge state across replicas.
- Without shared state, route `/challenge` and subsequent `/get-key` for the same caller to the same instance (session affinity/stickiness).
- If this is misconfigured, expect intermittent `invalid_challenge` failures.

---

## 8) Common mistakes to avoid

- Treating this as a generic "Phala deployment" guide.
- Reusing unpinned or unsigned policy inputs.
- Enabling mock attestation in production.
- Sharing one KMS across unrelated release cohorts without explicit policy governance.
- Mixing debug profile nodes with production key-release policy.

---

## Related docs

- [Platform runbooks index](README.md)
- [Trust & verification](../../release/trust-and-verification.md)
- [Generate release-pinned `merod` config](../../../scripts/policy/generate-merod-kms-phala-attestation-config.sh)
- [KMS service reference](../../../mero-kms/README.md)
