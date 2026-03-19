# MRTD and RTMR0–3: Differentiation and Portability

Two critical requirements:

1. **Differentiate the three images** (debug, debug-read-only, locked-read-only) — different security profiles must produce different attestation measurements.
2. **Portability** — once built, an image must run anywhere and produce the same measurements (so a single policy works everywhere).

---

## KMS Deployment Options

| Option | Platform | Measurements | Portability | Control |
|--------|----------|--------------|-------------|---------|
| **1. Phala (current)** | Phala dstack | compose-hash, instance-id, app-id | ❌ instance-id varies per CVM | Limited |
| **2. Phala (stabilized)** | Phala dstack | compose-hash only (if Phala supports) | ⚠️ Depends on Phala | Limited |
| **3. GCP (proposed)** | GCP TDX | MRTD, RTMR0–3 (kernel cmdline + calimero-init) | ✅ Same image → same measurements | Full |

---

## Option 3: Migrate KMS to GCP (Recommended)

Run KMS on GCP TDX VMs, like node-image-gcp. You get full control, stable measurements, and the same attestation model as nodes.

### Why GCP Works

- **GCP TDX** measures kernel cmdline (RTMR2) and supports RTMR3 extend via sysfs (`/sys/class/misc/tdx_guest/mr/rtmr3:sha384`).
- **calimero-init** already extends RTMR3 with `role:profile:root_hash` — same pattern as nodes.
- **No instance-id** in the verified measurements — MRTD/RTMR0–3 are deterministic for the same image.
- **Same tooling** as node-image-gcp: Packer, ITA verification, `published-mrtds.json`.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ GCP TDX VM (KMS image)                                           │
│  - calimero.role=kms calimero.profile=<profile> in kernel       │
│  - calimero-init extends RTMR3 with role+profile+root_hash        │
│  - mero-kms-gcp: native TDX quote + local key derivation         │
│  - /attest, /challenge, /get-key, /health                         │
└─────────────────────────────────────────────────────────────────┘
```

### Implementation Plan

#### Phase 1: mero-kms-gcp (Rust)

Create `mero-kms-gcp` (or add GCP backend to mero-kms) with:

| Component | Phala (dstack) | GCP replacement |
|-----------|----------------|-----------------|
| **Quote generation** | `DstackClient::get_quote()` | `calimero_tee_attestation::generate_attestation()` (configfs-tsm) |
| **Key derivation** | `DstackClient::get_key()` | Local: HKDF(peer_id, master_secret) or GCP Cloud KMS envelope |
| **RTMR3 extension** | `dstack_attest::emit_runtime_event()` | calimero-init at boot (sysfs) — no app-side extend needed |

Key derivation options for GCP:

- **A. Local HKDF**: Master secret from GCP Secret Manager (injected at boot) or env. Derive per-peer keys in memory. Simple, no external KMS calls.
- **B. GCP Cloud KMS**: Use Cloud KMS for envelope encryption. KMS calls GCP API; key material stays in KMS.

#### Phase 2: KMS Packer image

New `mero-tee/kms-image-gcp/` (mirror `node-image-gcp`):

- Packer build with Ansible role `merotee-kms`:
  - `calimero.role=kms`, `calimero.profile=<profile>` in kernel cmdline (RTMR2)
  - calimero-init extends RTMR3 with `calimero-rtmr3-v2:kms:<profile>:<root_hash>`
  - systemd runs `mero-kms-gcp` (not merod)
  - Expose `/attest` and `/health` on port 8080 (same as Phala KMS)
- Three profiles: debug, debug-read-only, locked-read-only
- Output: GCP images `mero-kms-ubuntu-*-<profile>-<version>`

#### Phase 3: Release workflow

`release-kms-gcp.yaml` (parallel to `release-node-image-gcp.yaml`):

1. Build KMS images per profile (Packer).
2. Create attestation VMs from each image.
3. Call `/admin-api/tee/attest`, verify via ITA, extract policy candidates.
4. Assemble `kms-phala-attestation-policy.<profile>.json` (or `kms-gcp-attestation-policy.<profile>.json`).
5. Publish under `mero-kms-vX.Y.Z` (or new tag `mero-kms-gcp-vX.Y.Z`).

#### Phase 4: MDMA GCP KMS provider

Add `gcp_kms_provider.py` in MDMA dispatcher:

- Create GCP TDX VM from KMS image (like `gcp_nodes.create_node` but for KMS).
- Use same GCP credentials, project, zone.
- KMS deployment type: user selects "Phala" or "GCP".
- KMS URL: derived from VM external IP or load balancer.

#### Phase 5: Compatibility and rollout

- Update compatibility map to support both Phala and GCP KMS.
- merod: already supports policy-based verification; point to GCP KMS policy URL.
- Deprecate Phala KMS once GCP path is stable.

### Effort Estimate

| Phase | Effort | Dependencies |
|-------|--------|--------------|
| 1. mero-kms-gcp | 2–3 weeks | Key derivation design |
| 2. KMS Packer image | 1–2 weeks | Phase 1 |
| 3. Release workflow | 1 week | Phase 2 |
| 4. MDMA GCP KMS | 1 week | Phase 2 |
| 5. Compatibility | ~1 week | Phases 1–4 |

### Benefits

- **Stable measurements**: Same image → same MRTD/RTMR0–3 on any GCP TDX VM.
- **Full control**: No Phala/dstack dependency; you own the full stack.
- **Consistency**: Same attestation model as node-image-gcp (kernel cmdline, calimero-init).
- **Differentiation**: RTMR2 and RTMR3 differ per profile via kernel params and init.

### Next Steps

1. Decide on key derivation (local HKDF vs GCP Cloud KMS).
2. Create `mero-kms-gcp` crate or add GCP backend to `mero-kms`.
3. Add `kms-image-gcp` Packer + Ansible (clone node-image-gcp structure).
4. Add `release-kms-gcp.yaml` workflow.
5. Add `gcp_kms_provider` to MDMA dispatcher.

---

## Phala-Specific: How Measurements Are Generated

From [Phala attestation docs](https://docs.phala.com/phala-cloud/attestation/verifying-attestation), the **RTMR3 event log** records events during boot in this order:

| Order | Event | Who sets it | Customizable? |
|-------|-------|-------------|---------------|
| 1 | `key-provider` | Platform (KMS that distributed keys) | No |
| 2 | `instance-id` | Platform (unique CVM identifier) | **No** |
| 3 | `compose-hash` | Platform (SHA256 of app-compose.json) | Via compose content |
| 4+ | `calimero.kms.profile=<profile>` | Your app (`emit_runtime_event`) | Yes |

The hash chain: `RTMR3_new = SHA384(RTMR3_old || SHA384(event))`. Instance-id is in the chain before compose-hash and your app events.

### Relevant Phala/Dstack Repos

- [Phala-Network/dstack](https://github.com/Phala-Network/dstack) — Phala's fork of Dstack-TEE/dstack
- [Dstack-TEE/dstack](https://github.com/Dstack-TEE/dstack) — Upstream; verifier, dstack-mr, attestation
- [Phala-Network/phala-cloud](https://github.com/Phala-Network/phala-cloud) — Cloud API, CLI, Terraform
- [Phala-Network/trust-center](https://github.com/Phala-Network/trust-center) — Reference verification
- [RTMR3 Calculator](https://rtmr3-calculator.vercel.app/) — Compose hash + event log → final RTMR3

### Tweaks You Can Try (Phala)

1. **Compose-hash stability**  
   - Use image digest: `image: ghcr.io/.../mero-kms-phala@sha256:...`  
   - Canonical YAML (key order, no extra fields)  
   - Same compose in probe and MDMA  
   - [RTMR3 Calculator](https://rtmr3-calculator.vercel.app/) to verify compose-hash

2. **Ask Phala for instance-id options**  
   - Open an issue or contact support: [support@phala.network](mailto:support@phala.network), [Discord](https://discord.gg/phala-network)  
   - Ask: Can instance-id be omitted, fixed, or made deterministic for same image/compose?  
   - Or: Is there a “verification mode” that only checks compose-hash (and app events) and ignores instance-id?

3. **Use allowlists for RTMR3**  
   - If you must stay on Phala: maintain an allowlist of observed RTMR3 values per profile  
   - Add new values when deploying; weakens security and does not scale

4. **Contribute upstream**  
   - [Dstack-TEE/dstack](https://github.com/Dstack-TEE/dstack) — Issues/PRs for instance-id behavior  
   - [Phala-Network/dstack](https://github.com/Phala-Network/dstack) — Phala-specific changes

**Bottom line**: instance-id is platform-controlled and not customizable today. Portability on Phala depends on Phala adding a way to make or ignore instance-id.

---

## Phala Portability (Option 2)

If staying on Phala:

1. **Align compose generation** — Probe and MDMA use the same template (`scripts/phala/kms-compose-template.yaml`) and substitute (image_ref, service_port).
2. **Use image digest** — `image: ghcr.io/.../mero-kms-phala@sha256:...` for reproducibility.
3. **Confirm with Phala** — What exactly is hashed for `compose_hash`? If instance-id or deployment name is included, portability is not achievable without Phala changes.
