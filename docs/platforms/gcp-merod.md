# GCP platform: deploy `merod` locked images (node plane)

This runbook is for operating the **GCP node image plane**.

It is **not** the KMS-plane deployment guide.  
For KMS on Phala, use [phala-kms.md](phala-kms.md).

---

## 1) Scope and responsibility

In the GCP lane:

- `mero-tee` builds and signs locked `merod` image artifacts and publishes MRTD policy data.
- Operators deploy those images on GCP TDX-capable instances.
- Operators verify deployed measurements against signed release assets.

This lane focuses on **node image trust and measurement verification**.

---

## 2) What is released for this lane

Locked-image assets are published under tag `locked-image-vX.Y.Z` and include:

- `published-mrtds.json`
- `merod-locked-image-policy.json`
- `mrtd-*.json` profiles
- `merod-locked-image-checksums.txt`
- `merod-locked-image-attestation-bundle.tar.gz`
- signed sidecars (`.sig`, `.pem`) and provenance/SBOM assets

---

## 3) Verify locked-image release assets first

```bash
TAG=2.1.10
scripts/verify-node-image-gcp-release-assets.sh "${TAG}"
```

The verifier resolves `locked-image-v${TAG}` automatically when needed.

---

## 4) Deploy a pinned locked image on GCP

Choose the profile that matches your risk/operability requirements:

- `debug`
- `debug-read-only`
- `locked-read-only` (recommended production baseline)

Provision TDX-capable instances and pin to the exact image/version you verified.
Avoid mutable deployment references.

For image build and publishing details, see:

- [packer/gcp/merod/README.md](../../packer/gcp/merod/README.md)

---

## 5) Verify runtime measurements after boot

Use published measurements to verify running node state:

- [Verify MRTD guide](../verify-mrtd.md)

This confirms the deployed node measurement matches the signed allowlist for the
selected release/profile.

---

## 6) Interaction with `core` attestation paths

`core` contains generic attestation tooling and TEE-mode configuration docs, but
this GCP lane in `mero-tee` is specifically about signed locked-image artifacts
and operator-side measurement validation.

Reference:

- [core docs/tee-mode.md](https://github.com/calimero-network/core/blob/master/docs/tee-mode.md)

---

## 7) Common mistakes to avoid

- Treating this lane as equivalent to the Phala KMS lane.
- Skipping release signature verification before image rollout.
- Mixing profile measurements across releases.
- Assuming artifact signatures alone prove runtime state without quote/MRTD checks.

---

## Related docs

- [Platform runbooks index](README.md)
- [Architecture & verification boundaries](../ARCHITECTURE.md)
- [Trust & verification](../TRUST_AND_VERIFICATION.md)
