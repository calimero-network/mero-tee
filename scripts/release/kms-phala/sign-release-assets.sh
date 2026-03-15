#!/usr/bin/env bash
set -euo pipefail

# Sign all KMS release trust assets with keyless Sigstore.
# Requires cosign to be available and release assets to be staged in
# `artifacts/` and `release-assets/`.

assets_for_rekor=(
  artifacts/*.tar.gz
  release-assets/kms-phala-checksums.txt
  release-assets/kms-phala-attestation-policy.json
  release-assets/kms-phala-attestation-policy.debug.json
  release-assets/kms-phala-attestation-policy.debug-read-only.json
  release-assets/kms-phala-attestation-policy.locked-read-only.json
  release-assets/kms-phala-container-metadata.json
  release-assets/kms-phala-container-sbom.spdx.json
  release-assets/kms-phala-binaries-sbom.spdx.json
  release-assets/kms-phala-trust-bundle.tar.gz
  release-assets/kms-phala-compatibility-map.json
)

for asset in "${assets_for_rekor[@]}"; do
  base_name="$(basename "${asset}")"
  cosign sign-blob \
    --yes \
    --output-signature "release-assets/${base_name}.sig" \
    --output-certificate "release-assets/${base_name}.pem" \
    --bundle "release-assets/${base_name}.bundle.json" \
    "${asset}"
done

rekor_entries_json="$(
  for asset in "${assets_for_rekor[@]}"; do
    base_name="$(basename "${asset}")"
    bundle_file="release-assets/${base_name}.bundle.json"
    asset_sha256="$(sha256sum "${asset}" | awk '{print $1}')"
    sigstore_search_url="https://search.sigstore.dev/?hash=sha256:${asset_sha256}"
    log_index="$(jq -r '.verificationMaterial.tlogEntries[0].logIndex // .VerificationMaterial.tlogEntries[0].logIndex // .tlogEntries[0].logIndex // empty' "${bundle_file}")"
    integrated_time="$(jq -r '.verificationMaterial.tlogEntries[0].integratedTime // .VerificationMaterial.tlogEntries[0].integratedTime // .tlogEntries[0].integratedTime // empty' "${bundle_file}")"
    log_id="$(jq -r '.verificationMaterial.tlogEntries[0].logId.keyId // .VerificationMaterial.tlogEntries[0].logId.keyId // .tlogEntries[0].logId.keyId // empty' "${bundle_file}")"
    jq -nc \
      --arg asset "${base_name}" \
      --arg bundle_asset "${base_name}.bundle.json" \
      --arg hash "sha256:${asset_sha256}" \
      --arg sigstore_search_url "${sigstore_search_url}" \
      --arg log_index "${log_index}" \
      --arg integrated_time "${integrated_time}" \
      --arg log_id "${log_id}" \
      '{
        asset: $asset,
        bundle_asset: $bundle_asset,
        hash: $hash,
        sigstore_search_url: $sigstore_search_url,
        log_index: $log_index,
        integrated_time: $integrated_time,
        log_id: $log_id
      }'
  done | jq -s '.'
)"

jq -n \
  --arg tag "${PREP_VERSION}" \
  --arg run_id "${GH_RUN_ID}" \
  --arg run_attempt "${GH_RUN_ATTEMPT}" \
  --argjson entries "${rekor_entries_json}" \
  '{
    schema_version: 1,
    tag: $tag,
    workflow_run_id: $run_id,
    workflow_run_attempt: $run_attempt,
    generated_at: (now | todate),
    entries: $entries
  }' > release-assets/kms-phala-rekor-index.json

post_assets=(
  release-assets/kms-phala-rekor-index.json
  release-assets/kms-phala-release-manifest.json
)
for asset in "${post_assets[@]}"; do
  base_name="$(basename "${asset}")"
  cosign sign-blob \
    --yes \
    --output-signature "release-assets/${base_name}.sig" \
    --output-certificate "release-assets/${base_name}.pem" \
    --bundle "release-assets/${base_name}.bundle.json" \
    "${asset}"
done
