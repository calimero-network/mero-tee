# Direct Phala KMS Integration Design (No `mero-kms-phala` Intermediary)

Status: Draft  
Authors: Calimero engineering (proposed)  
Last updated: 2026-03-03

## 1. Purpose

This document explains how Calimero could run `merod` on Phala by requesting
storage keys directly from the dstack/Phala key system, without the
`mero-kms-phala` HTTP intermediary.

Goals:

1. Simplify architecture and reduce trust in custom middleware.
2. Enforce upgrades through governance (preferably onchain).
3. Preserve key continuity across approved upgrades.

## 2. Current vs Target Architecture

## 2.1 Current (today in this repo)

```text
merod -> mero-kms-phala (/challenge,/get-key) -> dstack socket (/GetKey)
```

- `mero-kms-phala` verifies `merod` quote and policy.
- `mero-kms-phala` receives plaintext key bytes and returns them to `merod`.
- Policy is currently configured mainly via environment variables.

## 2.2 Target (direct integration)

```text
merod -> dstack socket (/GetKey)
           \-> dstack/Phala KMS authorization backend (Cloud or Onchain)
```

- `merod` calls dstack client directly.
- Policy authorization is handled by Phala KMS governance model.
- No custom key-release HTTP service in the middle.

## 3. How Phala KMS Works

At runtime, an app inside a CVM uses the local dstack socket
(`/var/run/dstack.sock`) to request deterministic keys by path.

Key points:

- Key derivation is deterministic for the same app identity and path.
- App identity and measurements are validated via attestation and policy.
- Governance model determines who can approve code/measurement changes.

Phala offers two governance modes:

1. **Cloud KMS** (centralized governance by platform operator)
2. **Onchain KMS** (smart-contract governance, distributed enforcement)

For security-sensitive production, this design assumes **Onchain KMS**.

## 4. Governance Model (Onchain) in Practice

## 4.1 Contracts and responsibilities

- **DstackKms contract** (global governance)
  - Allowed KMS program/measurement set
  - Allowed OS image hashes
  - App registration and KMS authorization checks
- **DstackApp contract** (per-app policy)
  - Allowed compose hashes for app upgrades
  - Optional device restrictions

Operational owner should be a multi-sig or timelock-controlled contract.

## 4.2 What is governed

For key release authorization, policy typically includes:

- app identity (`app-id`)
- code identity (`compose-hash`)
- system identity (`os image hash`, measurements)
- TCB health requirements
- optional device constraints

Any policy expansion (new code hash, new image hash, new KMS measurement) is an
explicit governance transaction and therefore auditable.

## 4.3 Authorization flow

When `merod` calls local `GetKey(path)`:

1. Attestation/boot information is evaluated by KMS authorization logic.
2. Governance policy is checked (onchain contract state).
3. If permitted, key is derived and returned.
4. If denied, request fails and startup should fail closed.

## 5. Direct `merod` Integration Design

## 5.1 Node-side implementation

`merod` uses dstack SDK client directly:

- mount `/var/run/dstack.sock` into `merod` container,
- call `GetKey(path)` at startup,
- decode and use key for storage encryption.

Suggested key path:

`calimero/merod/storage/v1/<peer_id>`

Rules:

- keep namespace stable for continuity,
- increment namespace version only for explicit cryptographic migrations.

## 5.2 Startup sequence

```text
1. merod boots
2. merod connects to /var/run/dstack.sock
3. merod requests GetKey(path = calimero/merod/storage/v1/<peer_id>)
4. KMS authorization validates app identity + policy
5. key returned to merod
6. merod unlocks storage and continues startup
```

Failure behavior:

- Any key request denial must abort startup in production mode.

## 5.3 Socket access hardening

- Only `merod` service should mount `dstack.sock`.
- No debug sidecars with socket access in production.
- Use immutable images by digest.

## 6. Upgrade Governance Runbook

## 6.1 Compatible app upgrade (no key rotation)

1. Build new app image/compose.
2. Compute new compose hash.
3. Submit governance proposal to allow new compose hash.
4. Wait timelock/multi-sig approvals.
5. Deploy canary.
6. Validate key fetch + storage unlock.
7. Roll out fleet.
8. Remove old compose hash after soak period.

Because app identity and key path remain stable, storage key remains stable.

## 6.2 OS/KMS upgrade

If policy includes OS/KMS measurement gating:

1. Add new allowed OS image hash / KMS measurements in governance.
2. Deploy new infrastructure.
3. Verify successful boot and key release.
4. Remove old values after soak.

## 6.3 Emergency rollback

1. Re-enable prior approved hashes/measurements if already removed.
2. Roll back deployment.
3. Confirm key continuity via successful data decrypt/startup.

## 7. Key Continuity and Migration

## 7.1 Continuity conditions

Same key is expected if all remain stable:

- app identity domain expected by KMS governance,
- derivation path,
- key derivation algorithm/version.

## 7.2 Intentional key rotation

Use explicit namespace bump:

- from `.../v1/<peer_id>` to `.../v2/<peer_id>`.

Then run controlled data re-encryption migration.

## 8. Security Properties and Trade-offs

## 8.1 Advantages vs current intermediary model

- Smaller attack surface (remove custom key-release service).
- Less chance of policy drift in env var configs.
- Governance-based upgrade authorization becomes primary control plane.

## 8.2 Residual risks

- If governance keys/process are compromised, policy can be changed maliciously.
- If `merod` image itself is approved but malicious, it can exfiltrate after
  receiving keys.
- Cloud KMS mode is operationally simpler but more centralized trust than
  onchain mode.

## 8.3 Comparison summary

| Model | Complexity | Key exfil risk from custom middleware | Upgrade governance strength |
|---|---|---|---|
| Current (`mero-kms-phala`) | Medium | Higher | Medium (env-driven unless extended) |
| Hybrid mutual-attestation (Option 2) | Medium-high | Medium | High |
| Direct dstack + onchain governance | Medium | Lower | High |

## 9. Migration Plan from Current Setup

## Phase A - Preparation

1. Define final key path namespace (`calimero/merod/storage/v1/<peer_id>`).
2. Confirm it maps to current effective key identity (or plan one-time migration).
3. Establish governance ownership model (multi-sig + timelock).

## Phase B - Dual-path implementation

1. Add direct dstack key client path in `merod`.
2. Keep existing `mero-kms-phala` flow behind feature flag for fallback.
3. Add startup telemetry to compare key-release success rates.

## Phase C - Governance cutover

1. Enable onchain policy for target app identity.
2. Approve current compose hash and required infrastructure hashes.
3. Run canary with direct path.

## Phase D - Full cutover

1. Roll out direct path.
2. Remove `mero-kms-phala` dependency from production compose.
3. Revoke legacy policy paths not needed anymore.

## 10. Open Questions

1. Which exact onchain network(s) are required (Ethereum/Base)?
2. Required timelock duration for production upgrades?
3. Is per-device binding required, or app-level only?
4. Should `merod` also verify and persist key release proof artifacts?

## 11. Recommendation

For the "no intermediary that can be tricked" objective, prefer:

1. **Direct dstack integration in `merod`**, and
2. **Onchain KMS governance** for upgrade authorization.

Keep `mero-kms-phala` only as temporary compatibility fallback during migration.
