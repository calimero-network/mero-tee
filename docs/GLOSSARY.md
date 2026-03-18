# Terminology Glossary

This glossary defines canonical naming used across docs, workflows, scripts,
and release assets.

## Lanes

| Term | Meaning |
|---|---|
| **Mero KMS TEE lane** | KMS service lane (`mero-kms-phala`) for TEE key-release operations. |
| **Mero Node TEE lane** | Node image build/release lane (`node-image-gcp`) for TDX node images. |
| **kms-phala lane** | Legacy alias for **Mero KMS TEE lane** (artifact/workflow naming compatibility). |
| **node-image-gcp lane** | Legacy alias for **Mero Node TEE lane** (artifact/workflow naming compatibility). |
| **KMS plane** | Operational surface for KMS deployment and key release decisions. |
| **Node plane** | Operational surface for node image build, rollout, and measurement verification. |

## Services and components

| Term | Meaning |
|---|---|
| **mero-kms-phala** | Rust KMS binary/service in `mero-kms/`. |
| **merod** | Node runtime from `calimero-network/core`. |
| **dstack** | Key derivation/quote provider used by the Mero KMS TEE lane. |

## Attestation terms

| Term | Meaning |
|---|---|
| **MRTD** | Firmware/root measurement for TDX guest trust chain. |
| **RTMR0..3** | Runtime measured registers; include launch/runtime state measurements. |
| **TCB status** | Trusted Computing Base status (for example `UpToDate`). |
| **Quote** | Attestation evidence emitted by TEE runtime. |
| **Allowlist** | Policy-approved list of acceptable measurement values. |

## Profiles

| Term | Meaning |
|---|---|
| **debug** | Non-production profile with relaxed hardening assumptions. |
| **debug-read-only** | Intermediate profile for read-only posture in non-production contexts. |
| **locked-read-only** | Production profile baseline. |
| **profile pinning** | Binding selected profile to image/runtime with override restrictions. |

## Release and governance

| Term | Meaning |
|---|---|
| **policy registry** | `policies/index.json` mapping versions to policy files and tags. |
| **policy promotion** | PR-reviewed update of versioned policy files from staged candidates. |
| **umbrella release** | Draft/index release linking component releases for the same version. |
| **release-version-sync guard** | CI enforcement that KMS/node version bump files remain aligned. |

## Naming guidance

- Prefer lane names **Mero KMS TEE lane** and **Mero Node TEE lane** in prose.
- Keep legacy identifiers (`kms-phala`, `node-image-gcp`) only when referring to concrete workflow/script/asset names.
- Use exact workflow/script filenames when referring to automation behavior.
- Avoid inventing alternate names for existing profiles and release tags.
