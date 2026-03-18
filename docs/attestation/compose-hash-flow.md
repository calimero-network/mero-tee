# Compose hash data flow

How `compose_hash` flows from release to attestation verifier, and when mismatches occur.

## Data flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ Release process (release-kms-phala.yaml)                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Trigger staging probe per profile (debug, debug-read-only, locked)        │
│ 2. Probe deploys KMS in the Mero KMS TEE environment → /attest → attest-response.json │
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

The compose_hash is **computed by the KMS TEE platform/dstack** from the `app-compose.json` (Docker Compose + metadata). Per platform docs, RTMR3 includes `compose-hash` and `instance-id` as separate events.

**Why the same release (e.g. mero-kms-v2.1.73) produces different compose_hash when deployed:**

1. **Deployment-specific metadata** — If the hashed compose includes deployment name, app_id, instance-id, or env vars, each deployment gets a different hash. The release probe uses canonical names (`calimero-kms-debug`, `calimero-kms-debug-read-only`, `calimero-kms-locked-read-only`). **MDMA and production should use the same names** for compose_hash to match.

2. **Different compose rendering** — the platform may substitute instance-specific values (region, VM UUID, etc.) into the compose before hashing. Same image, different runtime context -> different hash.

3. **Different KMS build** — Custom or non-release image produces different hash.

4. **Platform/dstack version** — changes to how compose is hashed will change results.

**Bottom line:** If compose_hash includes deployment-specific data (not fully documented), the release compose_hash may never match a user's deployment. Compose hash would then prove "this exact deployment config" rather than "this release image". Confirm with the platform vendor what exactly is hashed.

## Recommended deployment names (probe + MDMA)

For compose_hash to match between release and production, use the same deployment names:

| Profile           | Deployment name              |
|-------------------|------------------------------|
| debug             | `calimero-kms-debug`         |
| debug-read-only   | `calimero-kms-debug-read-only` |
| locked-read-only  | `calimero-kms-locked-read-only` |

When creating a KMS deployment in MDMA, use the name that matches your image profile.

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
