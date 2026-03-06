# TEE verification for beginners

This guide is written for people with little or no prior TEE background.

Goal: help you understand **what to run**, **why you run it**, and **what each check proves** before you trust a release in production.

---

## 1) What problem are we solving?

When you download software from GitHub releases, you need to answer:

1. Is this artifact really from the expected project/release workflow?
2. Was it modified after release?
3. Does it match the attestation policy and compatibility mapping we expect?

In `mero-tee`, verification is split into two release families:

- **KMS release** on tag `mero-kms-vX.Y.Z` (example: `mero-kms-v2.1.10`)
- **node-image-gcp release** on tag `mero-tee-vX.Y.Z` (example: `mero-tee-v2.1.10`)

The scripts in this repo automate those checks.

These map to two operational lanes:

- **Phala KMS lane**: deploy/operate `mero-kms-phala`
- **GCP node lane**: deploy locked `merod` images and verify node measurements

---

## 2) Quick glossary (plain language)

- **TEE**: Trusted Execution Environment. Hardware-backed isolated execution.
- **Attestation**: cryptographic evidence describing what ran inside a TEE.
- **MRTD / RTMR**: measurement values used in TEE policy checks.
- **Policy**: allowlist of acceptable measurements.
- **Sigstore/Cosign**: keyless signing/verification system used for release assets.
- **Rekor**: transparency log for signatures.
- **SBOM**: software bill of materials.
- **Compatibility map**: which KMS release and node-image-gcp policy belong together.

---

## 3) Before you start

Install required tools used by the verification scripts:

- `bash`
- `jq`
- `curl`
- `git`
- `cosign`
- optional: `gh` (GitHub CLI; scripts can fall back to API downloads if unavailable)

Also choose the release version you want to verify, for example:

```bash
TAG=2.1.10
```

---

## 4) Recommended verification flow

## Step A — Verify KMS release assets

```bash
scripts/release/verify-kms-phala-release-assets.sh "${TAG}"
```

What this checks:

- required KMS assets exist on release `mero-kms-vTAG`
- checksums match binary archives
- release manifest and attestation policy are structurally valid
- container metadata matches manifest (digest/commit consistency)
- Sigstore signatures/certificates validate against expected workflow identity

Why it matters:

- proves KMS artifacts were produced by the expected CI identity and are internally consistent.

---

## Step B — Verify node-image-gcp release assets

```bash
scripts/release/verify-node-image-gcp-release-assets.sh "${TAG}"
```

What this checks:

- finds node-image-gcp assets (supports `mero-tee-v${TAG}` layout)
- validates required measurement/provenance assets and checksums
- verifies policy/provenance JSON structure and tag consistency
- verifies Sigstore signatures for node-image-gcp assets

Why it matters:

- proves node-image-gcp measurement assets and provenance are authentic and not tampered with.

---

## Step C — Run the aggregate verifier

```bash
scripts/release/verify-release-assets.sh "${TAG}"
```

What this checks:

- runs KMS verification and node-image-gcp verification together
- handles the split-tag layout (`mero-kms-vTAG` + `mero-tee-vTAG`) automatically

Why it matters:

- best single command for release acceptance checks.

---

## 5) What “success” means (and does not mean)

If scripts pass, you have strong evidence that:

- artifacts are signed by the expected GitHub workflow identity,
- downloaded files match signed hashes/manifests/policies,
- transparency and metadata references are present.
- the signed attestation policy/config material needed by `merod`/KMS is present and internally consistent.

When runtime attestation is actually enforced by `merod` + KMS, you also gain
evidence that the TEE measurements (MRTD/RTMR) match the approved policy.

It still does **not** prove:

- code is bug-free,
- every environment-specific config choice is safe (network policy, secret handling, endpoint exposure),
- every system outside the attested TEE boundary is uncompromised (CI, control plane, DNS, host networking, etc.).

You should still do:

- staged rollout,
- policy review,
- runtime quote/attestation enforcement in production paths,
- operational monitoring.

---

## 6) Common failures and interpretation

- `missing asset ...`  
  Release upload is incomplete or you are checking the wrong tag.

- `checksum mismatch ...`  
  File mismatch or corruption (or wrong artifact version).

- `no matching signatures` / identity mismatch  
  Signature cannot be validated against expected workflow identity.

- node-image-gcp verifier can’t find assets on `TAG`  
  Check `mero-tee-vTAG` release (the script now tries this automatically).

---

## 7) Optional deep checks

- Inspect Rekor index and Sigstore search links:
  - `kms-phala-rekor-index.json`
  - each entry includes `hash` and `sigstore_search_url`
- Compare compatibility map values against `policies/index.json`.
- Generate release-pinned merod attestation config:

```bash
scripts/policy/generate-merod-kms-phala-attestation-config.sh "${TAG}" https://<kms-url>/
```

---

## 8) Minimal command set for operators

If you only run one command, run:

```bash
scripts/release/verify-release-assets.sh "${TAG}"
```

If it passes, proceed with rollout using release-pinned config and digest-pinned artifacts.
