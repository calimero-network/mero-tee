# KMS policy input migration (version/profile-only)

Downstream deployers should use this runtime contract for `mero-kms-phala`:

- **Required**
- `MERO_KMS_VERSION` (for example `2.2.2`)
  - `MERO_KMS_PROFILE` (`debug`, `debug-read-only`, or `locked-read-only`)
  - `ENFORCE_MEASUREMENT_POLICY=true`
- **Do not set in release/probe deployments**
  - `USE_ENV_POLICY`
  - `ALLOWED_TCB_STATUSES`
  - `ALLOWED_MRTD`
  - `ALLOWED_RTMR0`
  - `ALLOWED_RTMR1`
  - `ALLOWED_RTMR2`
  - `ALLOWED_RTMR3`

Behavioral changes:

- KMS now fetches attestation policy from release assets using version/profile.
- If policy is unavailable, `/attest` remains available for diagnostics.
- `/get-key` is fail-closed and returns `policy_not_ready` until policy is available.

Legacy env-policy mode (`USE_ENV_POLICY=true` with `ALLOWED_*`) is kept only for
explicit air-gapped/legacy scenarios and should not be used in standard release flows.
