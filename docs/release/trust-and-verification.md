# Trust, Verification, and Measurements (Canonical Guide)

This is the **single canonical guide** for operators and clients validating trust in the `mero-tee` release and runtime model.

It replaces fragmented onboarding/measurement pages with one concrete flow.

## What gets released

Per version `X.Y.Z`, there are two signed artifact families:

1. **KMS family** on `mero-kms-vX.Y.Z`
   - `mero-kms-phala` binaries/container metadata
   - KMS attestation policy assets (profile-scoped + default alias)
   - compatibility map and signatures
2. **Node-image family** on `mero-tee-vX.Y.Z`
   - `published-mrtds.json` (profile measurement policy)
   - release provenance, checksums, SBOM, signatures

## What signatures prove (and what they do not)

- **Prove**: artifact provenance (expected CI workflow identity) and integrity.
- **Do not prove**: that your running deployment is currently in the approved state.

So you need **both**:
- release verification (artifact trust), and
- runtime attestation verification (state trust).

## Verification direction matrix (who verifies whom)

| Verifier | Subject | Evidence/API | Required checks |
|---|---|---|---|
| `merod` (client node) | KMS (`mero-kms-phala`) | `POST /attest` quote + report data | quote crypto validity, nonce/binding freshness, KMS TCB + MRTD + RTMR0..3 policy |
| KMS (`mero-kms-phala`) | `merod` node | `POST /challenge` + `POST /get-key` | peer signature/identity, challenge freshness, quote crypto validity, node TCB + MRTD + RTMR0..3 policy |
| Operator/Auditor | release assets | signatures/checksums/manifests/compat map | workflow identity, integrity, version/profile compatibility |

If any verification step fails, rollout/key-release must fail closed.

## Profile compatibility (debug vs production)

Three node profiles exist:
- `debug`
- `debug-read-only`
- `locked-read-only`

Use profile-isolated trust cohorts:

| Node profile | KMS policy/image cohort | Intended use |
|---|---|---|
| `debug` | debug-only | local/dev |
| `debug-read-only` | debug-read-only-only | integration/pre-production |
| `locked-read-only` | locked-read-only-only | production |

Never mix debug profile measurements into production key-release cohorts.

## Operator quick path (release acceptance)

```bash
TAG=2.1.10
scripts/release/verify-release-assets.sh "${TAG}"
```

Then inspect compatibility:

```bash
curl -fsSL \
  "https://github.com/calimero-network/mero-tee/releases/download/mero-kms-v${TAG}/kms-phala-compatibility-map.json" \
  | jq '.compatibility'
```

Confirm:
- `kms_tag == mero-kms-v${TAG}`
- `node_image_tag == mero-tee-v${TAG}`
- profile entries under `.compatibility.profiles.*` match your rollout profile
- policy URLs/hashes are from reviewed signed assets

## Client/node configuration (release-pinned)

Generate or apply release-pinned `merod` KMS attestation config:

```bash
scripts/policy/generate-merod-kms-phala-attestation-config.sh \
  --profile locked-read-only \
  "${TAG}" \
  https://<kms-url>/
```

```bash
scripts/policy/apply-merod-kms-phala-attestation-config.sh \
  --profile locked-read-only \
  "${TAG}" \
  https://<kms-url>/ \
  /path/to/merod-home \
  default
```

## Compose hash (KMS app identity)

For Phala KMS deployments, **compose_hash** proves which exact Docker Compose configuration is running. It is trustworthy only when extracted from a **verified attestation path** (quote verified + event log verified).

- **Do not** trust compose_hash from provisioning metadata or control-plane API alone.
- **Do** use compose_hash from signed release assets (`kms-phala-attestation-policy.<profile>.json` or `kms-phala-compatibility-map.json`), which is captured during staging probe from a quote-verified attestation.
- Operators must verify compose_hash from signed release assets when validating KMS attestation.

## Runtime node measurement verification (MRTD/RTMR)

### 1) Get observed values from a verified quote path
- Prefer a quote verification path (Intel collateral via verifier) that outputs MRTD/RTMR values.
- As a quick check, operators may read node admin API values, but quote-verified extraction is the strong path.

### 2) Compare against `published-mrtds.json`
- Match by **release + profile**.
- Require policy match for:
  - `allowed_mrtd`
  - `allowed_rtmr0`
  - `allowed_rtmr1`
  - `allowed_rtmr2`
  - `allowed_rtmr3`
  - allowed TCB statuses

### Why some RTMRs may match across different image profiles

This is expected in some cases and does **not** automatically indicate a bug.

- **MRTD** usually changes whenever measured image/rootfs content differs.
- **RTMR0/RTMR1** can match across profiles if early boot chain and firmware/kernel components are identical.
- **RTMR2/RTMR3** are more likely to diverge between profiles because cmdline/runtime extensions include role/profile/root-hash-sensitive material (`calimero.role`, `calimero.profile`, `calimero.root_hash`).

Practical rule:
- Do not infer compatibility from one field.
- Always enforce the full policy tuple (TCB + MRTD + RTMR0..3) for the selected profile.

## Workflow identity expectations

Expected signing workflows (on `master`):
- `release-kms-phala.yaml`
- `release-node-image-gcp.yaml`

OIDC issuer:
- `https://token.actions.githubusercontent.com`

## RTMR3 and image legitimacy

For a detailed description of how RTMR3 is extended at boot and how clients verify image legitimacy, see [RTMR3-based image legitimacy verification](rtmr3-image-legitimacy-verification.md).

## Related docs

- [Platform runbooks](../runbooks/platforms/README.md)
- [Release verification examples](verification-examples.md)
- [Architecture boundaries](../architecture/trust-boundaries.md)
- [Documentation source index](../DOCS_INDEX.md)
