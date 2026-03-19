# mero-kms-phala

Key release service for `merod` nodes running in a TEE.

`mero-kms-phala` validates node attestations and only releases storage keys when
the request satisfies both:

1. identity/freshness checks (challenge-response + peer signature), and
2. measurement policy checks (TCB status + MRTD/RTMR allowlists).

## Endpoints

### `POST /challenge`

Issue a short-lived, single-use challenge nonce.

Request:

```json
{
  "peerId": "12D3KooW..."
}
```

Response:

```json
{
  "challengeId": "a1b2c3d4...",
  "nonceB64": "base64-32-byte-nonce",
  "expiresAt": 1735689600
}
```

### `POST /get-key`

Verify the attestation and release a deterministic key from dstack KMS.

Request:

```json
{
  "challengeId": "a1b2c3d4...",
  "quoteB64": "...",
  "peerId": "12D3KooW...",
  "peerPublicKeyB64": "...",
  "signatureB64": "..."
}
```

The service verifies:

- challenge exists, is not expired, and is consumed once,
- `peerPublicKey` maps to claimed `peerId`,
- `signature` is valid for the signed payload,
- quote is cryptographically valid,
- quote report data contains:
  - challenge nonce in bytes `[0..32]`,
  - `sha256(peer_id)` in bytes `[32..64]`,
- quote measurements/TCB satisfy configured policy.

### `POST /attest`

Generate a fresh KMS quote so callers can verify KMS code/measurement before
requesting keys.

Request:

```json
{
  "nonceB64": "base64-32-byte-nonce",
  "bindingB64": "optional-base64-32-byte-binding"
}
```

Response:

```json
{
  "quoteB64": "...",
  "reportDataHex": "64-byte-report-data-hex",
  "eventLog": [],
  "vmConfig": "{...}"
}
```

`reportData` layout:

- bytes `[0..32]`: caller-provided nonce (freshness),
- bytes `[32..64]`: caller binding (or KMS default domain separator if omitted).

Recommended caller verification:

1. Verify quote cryptographically.
2. Verify `reportData[0..32]` matches nonce.
3. Verify `reportData[32..64]` matches expected binding.
4. Verify KMS measurements (MRTD/RTMR/TCB) against governed allowlist.
5. Only then call `/challenge` + `/get-key`.

## Configuration

### Policy source: release fetch (recommended)

The KMS fetches the attestation policy from the official release at boot using
its build-time version (`CARGO_PKG_VERSION`). No env var required (profile-aware):

```
https://github.com/calimero-network/mero-tee/releases/download/mero-kms-v{VERSION}/kms-phala-attestation-policy.{PROFILE}.json
```

`PROFILE` is selected from the image-pinned profile marker (`/etc/mero-kms/image-profile`).
For released profile images, deploy-time `KMS_POLICY_PROFILE` overrides are rejected.
`KMS_POLICY_PROFILE` is only used for legacy/non-pinned local runs.
At startup (when mock attestation is disabled), KMS attempts to emit a runtime
event `calimero.kms.profile=<profile>` to extend RTMR3 and bind measurements to
the selected profile cohort. If runtime extension is unavailable in a target
environment, KMS logs a warning and continues startup.
For backward compatibility, `locked-read-only` can fall back to `kms-phala-attestation-policy.json`.

This ensures the policy cannot be tweaked via env vars; it comes from the
canonical source. If the fetch fails, startup fails closed.

Production recommendation:

- keep release policy as primary source (KMS uses `CARGO_PKG_VERSION` from build);
- optionally verify policy with `MERO_KMS_POLICY_SHA256` when fetching from release;
- use `USE_ENV_POLICY=true` only for explicit air-gapped env-policy mode;
- treat startup failures on missing/invalid policy as fail-closed signals, not something to bypass.

### Policy source: env vars (air-gapped / legacy)

For air-gapped deployments or when the release is unreachable, set
`USE_ENV_POLICY=true` and provide policy via env vars.

Environment variables:

- `LISTEN_ADDR` (default: `0.0.0.0:8080`)
- `DSTACK_SOCKET_PATH` (default: `/var/run/dstack.sock`)
- `CHALLENGE_TTL_SECS` (default: `60`)
- `MAX_PENDING_CHALLENGES` (default: `10000`) – cap on unconsumed challenges
- `ACCEPT_MOCK_ATTESTATION` (default: `false`)
- `ENFORCE_MEASUREMENT_POLICY` (default: `true`)
- `KMS_POLICY_PROFILE` – `debug`, `debug-read-only`, or `locked-read-only` (legacy/non-pinned runs only)
- `MERO_KMS_POLICY_SHA256` – optional; when set, verifies the fetched policy matches this SHA256
- `USE_ENV_POLICY` – if `true`, use env vars instead of release fetch (air-gapped)
- `KEY_NAMESPACE_PREFIX` – key namespace prefix (default: `merod/storage`)
- `REDIS_URL` – optional Redis connection URL for shared challenge state
- `CORS_ALLOWED_ORIGINS` – comma-separated browser origin allowlist (CORS disabled if empty)
- `ALLOWED_TCB_STATUSES` (CSV, default: `UpToDate`)
- `ALLOWED_MRTD` (CSV of hex measurements)
- `ALLOWED_RTMR0` (CSV of hex measurements)
- `ALLOWED_RTMR1` (CSV of hex measurements)
- `ALLOWED_RTMR2` (CSV of hex measurements)
- `ALLOWED_RTMR3` (CSV of hex measurements)

Measurement values must be hex-encoded 48-byte values (96 hex chars, optional
`0x` prefix).

When strict policy is enabled (`ENFORCE_MEASUREMENT_POLICY=true`) and mock
attestation is disabled (`ACCEPT_MOCK_ATTESTATION=false`):

- `ALLOWED_MRTD` must contain at least one trusted value (or use release fetch mode).
- `ALLOWED_TCB_STATUSES` must not be empty.

## Production guidance

- Keep `ACCEPT_MOCK_ATTESTATION=false`.
- Keep `ENFORCE_MEASUREMENT_POLICY=true`.
- Use the `locked-read-only` image profile for production; do not rely on profile env overrides.
- Require both quote verification and measurement verification for key release.
- Pin trusted values from your built/deployed image:
  - MRTD (required),
  - RTMR0/1/2 (required boot/runtime chain),
  - RTMR3 (required application/compose/runtime extensions).
- Start with `ALLOWED_TCB_STATUSES=UpToDate`.
- Use a short challenge TTL (for example, `30-120` seconds).
- Keep `/challenge`, `/get-key`, and `/attest` on private trusted networks (TLS/mTLS recommended across hosts).
- Prefer `REDIS_URL` for HA deployments so challenge state is shared across KMS replicas.
- Keep cohort-specific key namespaces isolated (`KEY_NAMESPACE_PREFIX` + profile) so debug/pre-prod cannot collide with production keys.

Example:

```bash
export LISTEN_ADDR=0.0.0.0:8080
export DSTACK_SOCKET_PATH=/var/run/dstack.sock
export CHALLENGE_TTL_SECS=60
export ACCEPT_MOCK_ATTESTATION=false
export ENFORCE_MEASUREMENT_POLICY=true
export ALLOWED_TCB_STATUSES=UpToDate
export ALLOWED_MRTD=<trusted_mrtd_hex>
export ALLOWED_RTMR0=<trusted_rtmr0_hex>
export ALLOWED_RTMR1=<trusted_rtmr1_hex>
export ALLOWED_RTMR2=<trusted_rtmr2_hex>
export ALLOWED_RTMR3=<trusted_rtmr3_hex>
```

## Development mode

For local testing without real TDX hardware, you can set:

```bash
export ACCEPT_MOCK_ATTESTATION=true
```

Do not use mock attestation in production.

## Deployment

For deployment guides, see:

- [Phala KMS lane](https://github.com/calimero-network/mero-tee/blob/master/docs/runbooks/platforms/phala-kms.md) – deploy/operate `mero-kms-phala` on Phala
- [GCP node lane](https://github.com/calimero-network/mero-tee/blob/master/docs/runbooks/platforms/gcp-merod.md) – deploy locked `merod` images on GCP
