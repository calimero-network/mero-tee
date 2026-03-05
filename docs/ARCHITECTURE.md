# Architecture & Verification

## Overview

mero-tee provides:

1. **mero-kms-phala** – KMS for Phala CVM; validates attestation, releases storage keys
2. **GCP locked image** – Packer-built merod node images with TDX attestation; MRTDs published for verification

## Trust Model

```
┌─────────────────────────────────────────────────────────────────┐
│  mero-tee builds & publishes                                      │
│  • mero-kms-phala binaries                                        │
│  • GCP image MRTDs (published-mrtds.json)                         │
│  • Attestation artifacts, provenance                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Operators                                                        │
│  • Fetch published-mrtds.json from mero-tee releases             │
│  • Post-boot: compare node MRTD to published                     │
│  • Match → node runs expected image                               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Users                                                            │
│  • Trust: published MRTDs                                        │
│  • Optional: verify MRTD + attestation themselves (see [verify-mrtd.md](verify-mrtd.md)) │
│  • Full verification: reproducible build → same MRTD              │
└─────────────────────────────────────────────────────────────────┘
```

## Verification

### What Signing Proves

- **GPG/Sigstore**: File came from mero-tee maintainers; not tampered in transit
- **Does NOT prove**: Content is honest; build matches source

### What Reproducible Build Proves

- Anyone rebuilds from source → same MRTD
- Match with published MRTD → we built from that source
- Mismatch → we built something different

### Malicious Resistance

| Attack | Mitigation |
|--------|------------|
| Third-party forges MRTDs | Signing |
| We publish malicious MRTDs | Reproducible build (users can verify) |
| Malicious source | Open source audit; no crypto fix |
| Malicious binary in image | Reproducible merod build + provenance |

## GCP vs Phala

| | GCP | Phala |
|---|-----|-------|
| **TEE** | Intel TDX | dstack (TDX) |
| **Image** | Packer (this repo) | Docker Compose |
| **KMS** | None (no dstack) | mero-kms-phala (this repo) |
| **Measurements** | `published-mrtds.json` + `merod-locked-image-policy.json` | Per-deployment (MRTD/RTMR policy) |
