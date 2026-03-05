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

Implementation references:

- KMS verification and policy enforcement:
  - `crates/mero-kms-phala/src/handlers.rs`
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
scripts/verify-kms-phala-release-assets.sh "${TAG}"
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
      ALLOWED_TCB_STATUSES: "UpToDate"
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
```

Production guidance:

- Keep `ACCEPT_MOCK_ATTESTATION=false`.
- Pin MRTD (and preferably RTMR0-3) allowlists.
- Do not use mutable container tags (`:latest`).

---

## 5) Configure merod with release-pinned attestation policy

Use signed policy from the same reviewed release:

```bash
scripts/apply-merod-kms-phala-attestation-config.sh "${TAG}" http://mero-kms:8080/ /data default
```

This writes `tee.kms.phala.attestation.*` config values so `merod` verifies KMS
self-attestation (`/attest`) and enforces policy before key fetch.

---

## 6) Runtime checks

- KMS health:
  - `GET /health`
- KMS self-attestation endpoint:
  - `POST /attest`
- Key exchange endpoints:
  - `POST /challenge`
  - `POST /get-key`

The expected runtime sequence is documented in
[Architecture](../../architecture/trust-boundaries.md#attestation-enforcement-points).

---

## 7) Common mistakes to avoid

- Treating this as a generic "Phala deployment" guide.
- Reusing unpinned or unsigned policy inputs.
- Enabling mock attestation in production.
- Sharing one KMS across unrelated release cohorts without explicit policy governance.

---

## Related docs

- [Platform runbooks index](README.md)
- [Trust & verification](../../release/trust-and-verification.md)
- [Generate release-pinned `merod` config](../../../scripts/generate-merod-kms-phala-attestation-config.sh)
- [KMS service reference](../../../crates/mero-kms-phala/README.md)
