# GCP platform: deploy `merod` node-image-gcp images (node plane)

This runbook is for operating the **GCP node image plane**.

It is **not** the KMS-plane deployment guide.  
For KMS on Phala, use [phala-kms.md](phala-kms.md).

---

## 1) Scope and responsibility

In the GCP lane:

- `mero-tee` builds and signs `node-image-gcp` artifacts and publishes MRTD policy data.
- Operators deploy those images on GCP TDX-capable instances.
- Operators verify deployed measurements against signed release assets.

This lane focuses on **node image trust and measurement verification**.

---

## 2) What is released for this lane

node-image-gcp assets are published under tag `mero-tee-vX.Y.Z` and include:

- `published-mrtds.json`
- `node-image-gcp-policy.json`
- `mrtd-*.json` profiles
- `node-image-gcp-checksums.txt`
- `node-image-gcp-attestation-bundle.tar.gz`
- signed sidecars (`.sig`, `.pem`) and provenance/SBOM assets

---

## 3) Verify node-image-gcp release assets first

```bash
TAG=2.1.10
scripts/release/verify-node-image-gcp-release-assets.sh "${TAG}"
```

The verifier resolves `mero-tee-v${TAG}` automatically when needed.

---

## 4) Deploy a pinned node-image-gcp image on GCP

Choose the profile that matches your risk/operability requirements:

- `debug`
- `debug-read-only`
- `locked-read-only` (recommended production baseline)

Provision TDX-capable instances and pin to the exact image/version you verified.
Avoid mutable deployment references.

For image build and publishing details, see:

- [mero-tee/README.md](../../../mero-tee/README.md)

### Baked merod (v2.1.16+)

From v2.1.16 onward, `merod`, `meroctl`, and `mero-auth` are **baked into the image** at build time via the `calimero-core` role. The init service uses these binaries if present and does not download them at runtime.

- **No `merod-version` metadata required** for baked images.
- Legacy images (pre-2.1.16) still download merod at runtime and require `merod-version` metadata (core tag, e.g. `0.10.0`).
- The build uses `merodVersion` from `versions.json` (or `GATED_MEROD_VERSION` in CI) to fetch binaries from `calimero-network/core` during image build.

### Optional runtime metadata for `MERO_TEE_VERSION`

When creating instances, you can pass metadata key `tee-release-version`.
During boot, the init service maps it to `MERO_TEE_VERSION` for `merod` via
`/etc/calimero/merod.env`.

- If `tee-release-version` is set, `MERO_TEE_VERSION` is written and loaded.
- If `tee-release-version` is removed, `/etc/calimero/merod.env` is removed on
  next boot to avoid stale values.

---

## 5) Verify runtime measurements after boot

Use published measurements to verify running node state:

- [Verify MRTD guide](../operations/verify-mrtd.md)

This confirms the deployed node measurement matches the signed allowlist for the
selected release/profile.

---

## 6) Interaction with `core` attestation paths

`core` contains generic attestation tooling and TEE-mode configuration docs, but
this GCP lane in `mero-tee` is specifically about signed node-image-gcp artifacts
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
- [Architecture & verification boundaries](../../architecture/trust-boundaries.md)
- [Trust & verification](../../release/trust-and-verification.md)
