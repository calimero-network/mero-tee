# Compose hash data flow

How `compose_hash` flows from release to attestation verifier, and when mismatches occur.

## Data flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Release process (release-kms-phala.yaml)                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Trigger staging probe per profile (debug, debug-read-only, locked)        │
│ 2. Probe deploys KMS on Phala → /attest → attest-response.json               │
│ 3. verify_dstack_compose_hash.py:                                            │
│    - Replays RTMR3 from event_log, verifies vs quote                          │
│    - Extracts compose_hash from imr=3 "compose-hash" event payload           │
│    - Writes kms-app-identity.json                                             │
│ 4. Release embeds event_payload in kms-phala-compatibility-map.json          │
│    compatibility.profiles.<profile>.event_payload                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Attestation verifier                                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Fetches kms-phala-compatibility-map.json from GitHub release              │
│    https://github.com/calimero-network/mero-tee/releases/download/           │
│    <tag>/kms-phala-compatibility-map.json                                    │
│ 2. Extracts compose_hash from user's attestation event_log (same logic)      │
│ 3. Compares received vs compatibility.profiles.<profile>.event_payload        │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Extraction logic (parity)

Both Python (`verify_dstack_compose_hash.py`) and JS (`attestation.js`) use identical logic:

- Filter events with `imr === 3`
- Find event with `event === "compose-hash"`
- Payload must match `^[a-fA-F0-9]{64}$`
- `compose_hash = payload.toLowerCase()`

## When compose_hash can differ

The compose_hash is **computed by Phala/dstack** from the `app-compose.json` (Docker Compose + metadata). Per [Phala docs](https://docs.phala.com/phala-cloud/attestation/attestation-fields), RTMR3 includes `compose-hash` and `instance-id` as separate events.

**Why the same release (e.g. mero-kms-v2.1.73) produces different compose_hash when deployed:**

1. **Deployment-specific metadata** — If the hashed compose includes deployment name, app_id, instance-id, or env vars, each deployment gets a different hash. The release probe uses canonical names (`calimero-kms-debug`, `calimero-kms-debug-read-only`, `calimero-kms-locked-read-only`). **MDMA and production should use the same names** for compose_hash to match.

2. **Different env vars** — Probe and MDMA must pass the same `MERO_KMS_VERSION` and `MERO_KMS_PROFILE` values in compose. If these differ, compose_hash diverges and runtime policy selection diverges. See [MDMA compose alignment](#mdma-compose-alignment) below.

3. **Different compose YAML structure** — Key order and formatting affect the hash. MDMA must emit identical YAML to the probe (same key order: image, restart, ports, environment, volumes; port mapping `host:8080`; `LISTEN_ADDR: "0.0.0.0:8080"`).

4. **Different compose rendering** — Phala may substitute instance-specific values (region, VM UUID, etc.) into the compose before hashing. Same image, different runtime context → different hash.

5. **Different KMS build** — Custom or non-release image produces different hash.

6. **Phala/dstack version** — Changes to how compose is hashed will change results.

**Bottom line:** If compose_hash includes deployment-specific data (which Phala has not fully documented), the release's compose_hash will **never** match a user's deployment. Compose hash would then prove "this exact deployment config" rather than "this release image". Confirm with Phala what exactly is hashed.

**Rebuilds without version bump:** The compose includes the image digest. A rebuild with the same Cargo.toml version produces a different image digest → different compose → different compose_hash → attestation verifier fails. Policy measurements would also differ, so the KMS would fail to validate its own attestation. Both mechanisms catch unreleased rebuilds.

## Recommended deployment names (probe + MDMA)

For compose_hash to match between release and production, use the same deployment names:

| Profile           | Deployment name              |
|-------------------|------------------------------|
| debug             | `calimero-kms-debug`         |
| debug-read-only   | `calimero-kms-debug-read-only` |
| locked-read-only  | `calimero-kms-locked-read-only` |

When creating a KMS deployment in MDMA, use the name that matches your image profile.

## MDMA compose alignment

**Single source of truth:** Both the probe and MDMA use `scripts/phala/kms-compose-template.yaml` from mero-tee. The probe substitutes `__IMAGE_REF__`, `__SERVICE_PORT__`, `__MERO_KMS_VERSION__`, and `__MERO_KMS_PROFILE__` at workflow time; MDMA must substitute the same placeholders. This eliminates version/profile drift.

## Verification script

Run to verify the flow and check extraction parity:

```bash
# Verify release fetch and structure
./scripts/attestation/verify-compose-hash-flow.sh mero-kms-v2.1.73

# Also compare Python vs JS extraction on an attest-response
./scripts/attestation/verify-compose-hash-flow.sh mero-kms-v2.1.73 path/to/attest-response.json
```

## Debugging a mismatch

1. **Confirm extraction** — Run the verification script with your attest-response. Python and JS should produce the same compose_hash.
2. **Check release asset** — Fetch the compatibility map and verify `event_payload` values match what the verifier shows as "Expected".
3. **Compare event logs** — If your event log has a different `compose-hash` event payload than the probe's, the hashes will differ. This usually means different compose/config at runtime.
