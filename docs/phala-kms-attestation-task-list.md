# Phala KMS Attestation Migration Tasks (mero-tee)

Status: In progress  
Owner: mero-tee team  
Last updated: 2026-03-03

This checklist tracks `mero-tee` responsibilities for secure KMS self-attestation
rollout used by `merod` key retrieval.

Legend:

- `[x]` implemented in `mero-tee`
- `[ ]` pending in `mero-tee`
- `[~]` relevant but partially implemented (follow-up needed)
- `[n/a]` not owned by `mero-tee` (core/operator side)

## Phase 1: KMS contract + compatibility

- [x] Confirm `/attest` API contract is stable and documented.
  - Documented in `crates/mero-kms-phala/README.md`:
    - request: `nonceB64`, optional `bindingB64`
    - response: `quoteB64`, `reportDataHex` (plus `eventLog`, `vmConfig`)
  - Note: wire format is camelCase (`nonceB64`), not snake_case.
- [x] Guarantee `report_data_hex` layout is exactly:
  - bytes `[0..32]` = nonce
  - bytes `[32..64]` = binding
  - Enforced by implementation and unit test in `crates/mero-kms-phala/src/handlers.rs`.
- [~] Ensure `/attest` + `/challenge` + `/get-key` compatibility.
  - Endpoints are implemented and compatible by design.
  - Missing full end-to-end integration test in this repo.
- [ ] Add integration tests for:
  - successful `/attest` + `/challenge` + `/get-key`
  - invalid nonce/binding mismatch behavior
  - rejected measurement/TCB policy
  - mock quote behavior (dev-only path)
  - Current state: unit tests exist for policy rejection/acceptance, report-data layout,
    default binding, invalid base64 length, and peer-id spoofing; no full integration suite.

## Phase 2: signed policy/governance artifacts

- [x] Publish trusted KMS measurements (MRTD, optional RTMR0..3) as release artifacts.
  - `release-kms-phala.yaml` publishes `mero-kms-phala-attestation-policy.json`.
- [x] Ship artifacts per pinned release tag (never `latest`).
  - Release assets are tag-based and verifier scripts require explicit tag input.
- [x] Sign artifacts (`.sig`/`.pem`) and provide verification flow.
  - Sigstore keyless signing in release workflow.
  - Verification scripts: `scripts/verify-kms-phala-release-assets.sh`,
    `scripts/generate-merod-kms-phala-attestation-config.sh`,
    `scripts/apply-merod-kms-phala-attestation-config.sh`.
- [~] Document signature identity constraints (OIDC issuer + workflow identity).
  - Implemented in verification scripts and release workflow sanity checks.
  - Follow-up: add an explicit dedicated section in docs for these identity constraints.
- [x] Provide machine-readable policy format for downstream ingestion by core.
  - `mero-kms-phala-attestation-policy.json` schema and helper ingestion scripts are in place.
- [x] Automate staging measurement collection for policy candidates.
  - `kms-phala-staging-probe.yaml` + `scripts/extract_tdx_policy_candidates.py`.
- [x] Gate policy promotion through reviewed PR updates.
  - `kms-phala-policy-promotion-pr.yaml` writes `policies/kms-phala/<tag>.json`
    and opens a pull request for approval before release publication.
- [x] Use versioned policy registry as release input source of truth.
  - `release-kms-phala.yaml` reads `policies/index.json` and the mapped
    per-tag policy file instead of repository variable overrides.

## Phase 3: rollout and operational hardening

- [x] Document release-isolated deployment model:
  - old merod cohort -> old KMS deployment
  - new merod cohort -> new KMS deployment
  - avoid mixed cohorts by default
  - See `docs/kms-blue-green-rollout.md`.
- [x] Provide blue/green rollout playbook and rollback procedure.
  - See `docs/kms-blue-green-rollout.md`.
- [ ] Document load-balancer/session requirements so challenge state remains valid.
  - Needed because challenge state is in-memory and consumed per KMS instance.
- [ ] Define emergency measurement revoke process and communication runbook.

## Phase 4: observability and audits

- [ ] Add structured audit logs for attestation decisions:
  - measurement fingerprints
  - TCB status
  - policy version / source release
- [ ] Define minimum retention and incident response guidance.

## Not in mero-tee ownership

- [n/a] Core-side verification behavior and defaults in `merod` runtime (e.g. production
  default `tee.kms.phala.attestation.enabled=true`) are tracked in `core` task list.
- [n/a] Client-side binding mismatch enforcement in `merod` verification logic is owned by `core`.

## Notes

- Attestation must fail closed in production.
- Mock attestation acceptance is development-only.
- `core` (`merod`) performs caller-side attestation preflight verification; `mero-tee` owns
  KMS-side correctness, signed policy publication, and rollout guidance.
