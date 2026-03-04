# KMS Blue/Green Rollout Runbook (TEE Nodes)

This runbook defines the production rollout model for KMS-attested TEE nodes.

## Scope

- Applies to **TEE nodes only** (nodes with `[tee]` configured in `core`).
- Non-TEE nodes remain libp2p peers and do not use KMS.

## Goal

Avoid cross-version coupling and circular trust dependencies during upgrades:

- old TEE release nodes talk only to old KMS deployment,
- new TEE release nodes talk only to new KMS deployment.

## Inputs

For a target `mero-tee` tag `X.Y.Z`:

1. `mero-kms-phala-checksums.txt`
2. `mero-kms-phala-release-manifest.json`
3. `mero-kms-phala-attestation-policy.json`
4. Sigstore sidecars for each file (`.sig`, `.pem`)
5. Binary archives and their sidecars

All assets must be verified with:

```bash
scripts/verify_mero_kms_release_assets.sh X.Y.Z
```

## Blue/Green Deployment Steps

### 1. Keep old cohort pinned

- Keep old TEE nodes on old merod release and old KMS endpoint.
- Do not change old cohort KMS URL or attestation policy during new rollout.

### 2. Deploy new KMS (green)

- Deploy new `mero-kms-phala` release in a **separate** environment.
- Use a new service endpoint (DNS/URL) and independent rollout controls.
- Publish verified release assets for this tag.

### 2.5 Promote policy entry for this release tag

- Recommended: let `kms_policy_auto_pipeline.yaml` dispatch probe + promotion
  automatically after version bump merge.
- Fallback: run `kms_staging_probe_phala.yaml` and then `kms_policy_promotion_pr.yaml` manually.
- Merge the policy PR so `policies/mero-kms-phala/<X.Y.Z>.json` is present.
- Keep `policies/mero-kms-phala/index.json` updated as the historical registry.
- Release automation reads this registry entry for policy values.

### 3. Generate pinned merod TEE config

Generate config from signed policy artifact:

```bash
scripts/generate_merod_kms_attestation_config.sh X.Y.Z https://kms-green.example.com/ ./tee-kms.toml
```

This generates `[tee.kms.phala.attestation]` with release-pinned allowlists.

Or apply directly to an existing node config:

```bash
scripts/apply_merod_kms_attestation_config.sh X.Y.Z https://kms-green.example.com/ /data default
```

### 4. Deploy new TEE nodes (green)

- Deploy new TEE nodes using new merod release + generated TEE KMS config.
- Verify startup passes KMS `/attest` preflight before `/challenge` + `/get-key`.

### 5. Validate and cut over

- Validate cluster health, key access, and expected attestation behavior.
- Shift workload/traffic to new cohort according to your operational policy.

### 6. Decommission old cohort

- After stability window and rollback window expire, decommission old KMS and old TEE nodes.
- Revoke old allowlists/policies where applicable.

## Rollback

If green rollout fails:

- keep old cohort unchanged,
- route traffic back to old cohort,
- investigate and fix green KMS/TEE release out-of-band,
- redeploy green with a new pinned release tag.

## Guardrails

- Never auto-follow `latest` for attestation policy.
- Always pin to a reviewed, signed release tag.
- Fail closed if signature verification or attestation policy verification fails.
