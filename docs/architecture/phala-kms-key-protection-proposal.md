# Phala KMS Key Protection and Upgrade Continuity Proposal

Status: Draft  
Authors: Calimero engineering (proposed)  
Last updated: 2026-03-03

## 1. Executive Summary

This document proposes a hardened key-management model for `merod` on Phala that addresses two requirements:

1. Prevent key extraction even when operators can redeploy services.
2. Preserve storage-key continuity across service upgrades.

The current `mero-kms-phala` service enforces strong attestation policy checks (MRTD/RTMR/TCB), but it still handles plaintext keys in-process. That means anyone who can deploy modified KMS code can exfiltrate keys.

To satisfy the stronger requirement ("operator can redeploy, but still cannot extract keys"), we must move trust from deploy-time configuration to a separate attested key authority and governance-controlled policy. In short: **separate policy decisions from key material custody**.

## 2. Problem Statement

Current flow (simplified):

1. `merod` requests challenge from `mero-kms-phala`.
2. `merod` submits quote + identity proof to `/get-key`.
3. `mero-kms-phala` validates attestation and policy.
4. `mero-kms-phala` calls dstack `GetKey(path="merod/storage/<peer_id>")`.
5. dstack returns key bytes to `mero-kms-phala`.
6. `mero-kms-phala` returns key to `merod`.

Security properties today:

- Good: strong quote verification and measurement allowlists.
- Good: deterministic key continuity by key path.
- Gap: KMS process sees plaintext key bytes.

Consequence:

- If an attacker/operator can redeploy modified KMS code, they can log or exfiltrate returned key material.

## 3. Goals and Non-Goals

### Goals

- G1: Operator redeploy rights must not imply key extraction capability.
- G2: Compatible service upgrades must keep the same data key for the same node identity.
- G3: Image/measurement upgrades must be auditable and explicitly authorized.
- G4: Emergency rollback must be possible without key loss.

### Non-Goals

- NG1: Eliminate trust in TEE hardware vendors.
- NG2: Protect against runtime bugs in `merod` itself once it has valid key access.
- NG3: Replace the existing attestation stack immediately in one release.

## 4. Threat Model

### In scope

- Malicious/compromised operator with ability to redeploy KMS containers.
- Misconfiguration of allowlists (accidental broad policy).
- Replay of stale attestations.
- Unauthorized image upgrades that change measurements.

### Out of scope

- Full compromise of TEE hardware root of trust.
- Host-level denial-of-service.

## 5. Proposed Target Architecture

### 5.1 Principle: split control from custody

`mero-kms-phala` should not be the long-term custody point for plaintext data keys.

Proposed components:

1. **Attested key authority (custodian)**  
   - Dedicated KMS in TEE mode with stable root key lifecycle.  
   - Root key is bootstrapped in TEE and replicated only to authorized successor KMS instances.
2. **Policy/governance layer (authorizer)**  
   - Measurement and app-identity policy managed outside mutable container env vars.
   - Policy updates require explicit governance action (signed policy artifact or contract update).
3. **Requester (`merod`)**  
   - Receives keys only after quote verification against governed policy.
   - Verifies key-provider identity (root key / RA-TLS anchor).

### 5.2 Required property

Unauthorized redeploy of the "edge KMS service" must not give access to root key material or unrestricted key-derivation APIs.

### 5.3 Practical deployment shape

Two viable patterns:

- **Preferred:** `merod` receives keys directly from the attested key authority over RA-authenticated channel.
- **Interim-compatible:** keep `mero-kms-phala` as policy gateway, but have authority return requester-bound wrapped keys only (gateway never sees plaintext).

## 6. Policy Source of Truth

Today policy is mostly environment-driven (`ALLOWED_MRTD`, `ALLOWED_RTMR*`, `ALLOWED_TCB_STATUSES`), which is easy to redeploy and mutate.

Proposal:

1. Move production policy to a signed, versioned artifact or on-chain registry.
2. KMS accepts policy only if signature verifies against pinned governance key.
3. Runtime env vars may tighten policy but cannot broaden it beyond signed policy.
4. Policy history is append-only and auditable.

Minimum governed fields:

- Allowed TCB statuses.
- Allowed MRTD/RTMR sets.
- Allowed app identity namespace (e.g., app-id / compose-hash constraints).
- Allowed key-provider identities (KMS root public keys).

## 7. Key Derivation and Continuity Model

### 7.1 Stable namespace

Keep a versioned, immutable derivation namespace:

- `calimero/merod/storage/v1/<peer_id>`

Rules:

- Keep `v1` unchanged for compatible upgrades.
- Do not include mutable deployment metadata in the key path.
- `peer_id` must remain stable for a node that should retain data access.

### 7.2 Upgrade-safe key continuity

For compatible upgrades:

- Same root key + same derivation path => same storage key.

For intentional cryptographic migration:

1. Introduce `v2` path namespace.
2. Run explicit re-encryption migration.
3. Keep dual-read support during cutover.
4. Remove `v1` only after successful migration validation.

### 7.3 KMS authority upgrades

Use TEE-to-TEE onboarding/replication so successor KMS instances inherit the same root keys, gated by governance-approved measurements. This preserves deterministic outputs for existing paths across KMS upgrades.

## 8. Upgrade and Rollback Runbook

### 8.1 Image/policy upgrade (no key rotation)

1. Build and attest new image(s).
2. Add new measurements to governed allowlist while keeping old values.
3. Deploy new version.
4. Verify successful key fetch + data unlock.
5. Remove old measurements after soak period.

### 8.2 Emergency rollback

If new release fails:

1. Re-enable previous measurements.
2. Roll back image.
3. Confirm key continuity via known data decryption checks.

### 8.3 Forbidden operation

Never change derivation namespace/path during routine service upgrades. That is equivalent to key rotation and must follow a dedicated migration procedure.

## 9. Immediate Hardening (can be applied now)

Until target architecture is implemented, enforce the following:

1. `ACCEPT_MOCK_ATTESTATION=false`
2. `ENFORCE_MEASUREMENT_POLICY=true`
3. `ALLOWED_MRTD` set and restricted to trusted production profile(s)
4. Pin all production images by digest (no `:latest`)
5. Restrict who can change deployment config and secrets
6. Emit audit logs for each release decision:
   - peer ID
   - attested MRTD/RTMR hash fingerprints
   - policy version used
   - allow/deny result

This does not fully solve the redeploy-exfiltration problem, but reduces accidental policy bypass and improves detection.

## 10. Implementation Plan

### Phase 0 - Baseline hardening (1-2 sprints)

- Enforce strict production flags and measurement pinning.
- Add policy-versioned audit logging.
- Introduce operational runbook for old/new measurement overlap during upgrades.

### Phase 1 - Governed policy (2-4 sprints)

- Signed policy artifact format and verification in KMS startup path.
- Reject startup if policy signature invalid or policy missing required constraints.
- Remove broadening-by-env in production mode.

### Phase 2 - Key custody separation (4-8 sprints)

- Integrate dedicated attested key authority.
- Move to direct key release to requester or wrapped-key mode.
- Ensure edge gateway cannot access plaintext key bytes.

### Phase 3 - Full upgrade authority model

- Governance-controlled registration of allowed KMS and app measurements.
- Automated, auditable key-authority onboarding for KMS upgrades.

## 11. Acceptance Criteria

The proposal is considered implemented when:

1. Redeploying edge KMS alone cannot extract plaintext storage keys.
2. Compatible upgrades preserve key continuity with no data re-encryption.
3. Policy changes are signed/governed and fully auditable.
4. Rollback to prior measured version preserves key access.

## 12. Open Questions

1. Which governance source of truth is preferred: signed offline policy artifact, on-chain contract, or both?
2. Should wrapped-key mode be used as an interim bridge before direct requester-to-authority key exchange?
3. What is the required maximum overlap window for old/new measurements during rollout?
4. Should we enforce single-profile production policy (locked-read-only only) by default?

## 13. Decision

Recommended decision:

- Approve Phase 0 and Phase 1 immediately.
- Start design for Phase 2 with a hard requirement that edge-redeploy capability does not imply key extraction capability.
