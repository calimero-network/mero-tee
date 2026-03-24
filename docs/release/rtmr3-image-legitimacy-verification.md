# RTMR3-Based Image Legitimacy Verification

This document describes a safe end-to-end flow for **generating** attestation measurements (including RTMR3) at build/release time and **verifying** them at runtime so clients can trust that the image is legitimate.

## Overview

1. **Generate** (release workflow): Build images, attest them, publish signed policy with expected measurements.
2. **Verify** (client/KMS): Fetch signed policy, verify quote crypto, check quote measurements match policy allowlist.

RTMR3 is the user-extensible register; we extend it with `role:profile:root_hash` so each image produces a unique, unforgeable measurement.

---

## 1. What We Generate (Release Time)

### RTMR3 Extension Formula

calimero-init extends RTMR3 with:

```
extension_payload = "calimero-rtmr3-v2:role:profile:root_hash"
digest_written    = SHA384(extension_payload)  # 48 bytes binary
RTMR3_new        = SHA384(RTMR3_old || digest_written)
```

- **role**: `node` or `kms`
- **profile**: `debug`, `debug-read-only`, or `locked-read-only`
- **root_hash**: SHA256 of sorted file hashes (`/etc/calimero`, `/usr/local/lib/calimero`, `/etc/default/grub`, `/usr/local/bin/merod`, `/usr/local/bin/meroctl`, `/usr/local/bin/mero-auth`) — includes binaries so substitution changes attestation

The `calimero-rtmr3-v2` prefix versions the format; changes require a new prefix.

### Initial RTMR3 State (GCP TDX)

Before any extend, RTMR3 is platform-defined. On GCP TDX with a fresh boot, it is typically all zeros. If so:

```
RTMR3_initial = 48 bytes of 0x00
RTMR3_final   = SHA384(RTMR3_initial || SHA384("calimero-rtmr3-v2:node:locked-read-only:<root_hash>"))
```

This is deterministic: same inputs → same RTMR3. Auditors can recompute and compare to the published allowlist.

### Release Artifacts (Signed)

| Artifact | Purpose |
|----------|---------|
| `published-mrtds.json` | MRTD + RTMR0..3 allowlists per profile; measurement policy |
| `published-mrtds.json.sig` | Sigstore/cosign signature |
| `published-mrtds.json.pem` | Certificate for signature verification |
| `release-provenance.json` | Build metadata, workflow identity, compatibility |
| `release-provenance.json.sig` | Sigstore signature |

Measurements are captured from attested VMs (Intel ITA verification). Policy is signed by the release workflow; only the expected CI identity can produce valid signatures.

---

## 2. How the Client Verifies

### Merod Verifying KMS

1. **Fetch policy** from `mero-kms-vX.Y.Z` release (policy URL pinned by `MERO_KMS_VERSION` / `MERO_TEE_VERSION`).
2. **Verify policy signature** via Sigstore: workflow = `Release mero-kms`, repo = `calimero-network/mero-tee`, ref = `master`.
3. **Attest KMS**: `POST /attest` with nonce; receive quote.
4. **Verify quote**:
   - Cryptographic validity (Intel DCAP/collateral or ITA).
   - Nonce matches report_data[0..32].
   - MRTD, RTMR0, RTMR1, RTMR2, RTMR3 in policy allowlists.
   - TCB status in allowed set.
5. **Key release** only if all checks pass.

### KMS Verifying Node (merod)

1. **Fetch policy** (from release or env); contains `node_allowed_*` measurements.
2. **Challenge**: Node requests challenge; KMS issues nonce.
3. **Node attest**: Node produces quote with nonce + peer_id hash in report_data.
4. **Verify quote**: Same checks (crypto, nonce, app hash, MRTD + RTMR0..3 in allowlist).
5. **Key release** only if all checks pass.

### Operator / Auditor Verification

1. Download `published-mrtds.json` + `.sig` + `.pem` from release.
2. Verify signature (cosign verify-blob or equivalent).
3. Compare live node attestation (from admin API or attestation verifier) against allowlists.
4. Optionally: recompute expected RTMR3 from root_hash (if published) using the formula above and cross-check.

---

## 3. Binary swap attack (mitigated)

**Attack**: Replace `/usr/local/bin/merod` (or meroctl, mero-auth) with a different binary; boot the image; attestation still matches because the hash did not cover those files.

**Mitigation**: root_hash includes `/usr/local/bin/merod`, `/usr/local/bin/meroctl`, `/usr/local/bin/mero-auth`. Any substitution changes root_hash → different RTMR2/RTMR3 → attestation fails.

---

## 4. Safety Improvements

### 4.1 Boot-Resilient RTMR3 Extension

`calimero-init` attempts RTMR3 extension at boot and logs success/failure, but does not hard-fail node startup when the RTMR3 sysfs path is unavailable or write fails. This avoids taking down `locked-read-only` nodes due to platform/kernel differences while still producing RTMR3 when supported.

```bash
# In calimero-init.sh.j2:
if cat "$RTMR3_EXTEND_FILE" > "${RTMR3_SYSFS}" 2>/dev/null; then
  log "Extended RTMR3 for attestation (...)"
else
  log "WARN: RTMR3 extend write failed"
fi
```

Operational guidance:
- Treat RTMR3 extension as a measured signal, not a boot prerequisite.
- Enforce strictness at verification/policy time (see 4.4), e.g. reject all-zero or unexpected RTMR3 values for production cohorts.

### 4.2 Publish root_hash in Provenance

Add `root_hash` to profile-provenance / release-provenance so there is a signed binding:

```
{ profile, image, mrtd, root_hash, allowed_rtmr3, ... }
```

Operators and auditors can then:
- Verify the root_hash matches the attested image.
- Optionally recompute expected RTMR3 and compare to `allowed_rtmr3`.

### 4.3 RTMR3 Derivation Verification Script

Add a script (e.g. `scripts/attestation/verify-rtmr3-derivation.sh`) that:

- Inputs: `role`, `profile`, `root_hash` (from provenance).
- Computes: `expected_rtmr3 = SHA384(zeros_48 || SHA384("calimero-rtmr3-v2:role:profile:root_hash"))`.
- Compares to `allowed_rtmr3[0]` from `published-mrtds.json`.

If they match, the allowlist is consistent with the documented formula. Use with caution: only valid when RTMR3 initial state is known (e.g. zeros on GCP TDX).

### 4.4 Reject All-Zero RTMR3 in Policy Enforcement

In mero-kms (and any policy consumer), optionally reject quotes where `rtmr3` is all zeros when the policy expects an extended value. This catches images that failed to extend RTMR3 (e.g. kernel < 6.16) before they could obtain a key.

---

## 5. Trust Chain Summary

```
[Image build]  GRUB injects role, profile, root_hash → RTMR2
               calimero-init extends RTMR3 at boot

[Release]      CI attests VMs → captures MRTD, RTMR0..3
               Signs published-mrtds.json (Sigstore)
               Publishes to GitHub release

[Client]       Fetches policy from release
               Verifies policy signature (workflow identity)
               Gets quote from KMS/node
               Verifies quote crypto + measurements in allowlist
               Releases key only if all pass
```

The client trusts the image when:
1. Policy signature is valid (proves it came from release workflow).
2. Quote is cryptographically valid (proves TDX hardware attestation).
3. Quote measurements (MRTD + RTMR0..3) match the policy allowlist (proves same image as released).

---

## 6. Related Docs

- [Trust and Verification](trust-and-verification.md)
- [MRTD-RTMR Measurement Generation](MRTD-RTMR-measurement-generation.md)
- [Architecture Trust Boundaries](../architecture/trust-boundaries.md)
