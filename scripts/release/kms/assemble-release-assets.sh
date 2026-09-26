#!/usr/bin/env bash
set -euo pipefail

# Assemble the trust assets of a mero-kms release (release-kms.yaml) from what
# the earlier jobs produced. Run from the repository root.
#
# Inputs (files):
#   artifacts/*.tar.gz                                   the binary archives
#   probe-artifacts/kms-probe-<ver>-<profile>/kms-measurements.json
#                                                        ITA-verified KMS measurements
#                                                        (scripts/release/kms/run-cluster-probe.sh)
#   probe-artifacts/kms-probe-<ver>-<profile>/image.json the GCP image the probe booted
#   node-policy/published-mrtds.json                     node allowlists (mero-tee-v<ver>)
# Inputs (env): GH_REPOSITORY, GH_RUN_ID, GH_RUN_ATTEMPT, GH_WORKFLOW_NAME,
#   GH_REF_NAME, PREP_VERSION, PREP_KMS_RELEASE_TAG, PREP_TARGET_COMMIT.
#
# Outputs (release-assets/): kms-checksums.txt, kms-attestation-policy.<profile>.json
# and the kms-attestation-policy.json alias (= locked-read-only), which merod
# fetches and applies at `tee.kms.attestation`; kms-compatibility-map.json,
# kms-release-manifest.json, kms-trust-bundle.tar.gz and release-notes.md.

for var in GH_REPOSITORY GH_RUN_ID GH_RUN_ATTEMPT GH_WORKFLOW_NAME GH_REF_NAME PREP_VERSION PREP_KMS_RELEASE_TAG PREP_TARGET_COMMIT; do
  if [[ -z "${!var:-}" ]]; then
    echo "::error::${var} is required"
    exit 1
  fi
done

version="${PREP_VERSION}"
kms_tag="${PREP_KMS_RELEASE_TAG}"
node_tag="mero-tee-v${version}"
download_base="https://github.com/${GH_REPOSITORY}/releases/download"
node_policy_url="${download_base}/${node_tag}/published-mrtds.json"
node_policy_file="node-policy/published-mrtds.json"
profiles=(debug debug-read-only locked-read-only)
metrics=(mrtd rtmr0 rtmr1 rtmr2 rtmr3)
out="release-assets"
mkdir -p "${out}"

fail() {
  echo "::error::$*"
  exit 1
}

[[ -f "${node_policy_file}" ]] || fail "Node policy not found at ${node_policy_file}"
compgen -G "artifacts/*.tar.gz" >/dev/null || fail "No binary archives in artifacts/"

(cd artifacts && sha256sum ./*.tar.gz | sed 's#  \./#  #' | sort -k2) > "${out}/kms-checksums.txt"

for profile in "${profiles[@]}"; do
  dir="probe-artifacts/kms-probe-${version}-${profile}"
  [[ -f "${dir}/kms-measurements.json" ]] || fail "Probe measurements not found at ${dir}/kms-measurements.json"
  [[ -f "${dir}/image.json" ]] || fail "Probe image metadata not found at ${dir}/image.json"
  jq -e --arg p "${profile}" --arg v "${version//./-}" \
    '.name == ("merotee-kms-" + $p + "-" + $v) and .family == ("merotee-kms-" + $p)' \
    "${dir}/image.json" >/dev/null \
    || fail "${dir}/image.json is not the release image merotee-kms-${profile}-${version//./-} in family merotee-kms-${profile}"
  for key in allowed_tcb_statuses "${metrics[@]/#/allowed_}"; do
    jq -e --arg k "${key}" '.policy[$k] | type == "array" and length > 0' "${dir}/kms-measurements.json" >/dev/null \
      || fail "KMS ${profile} measurements have no ${key}"
    jq -e --arg p "${profile}" --arg k "${key}" '.profiles[$p][$k] | type == "array" and length > 0' "${node_policy_file}" >/dev/null \
      || fail "${node_tag} has no ${profile} node ${key}"
  done
done

kms_measurements() { printf 'probe-artifacts/kms-probe-%s-%s/kms-measurements.json' "${version}" "$1"; }
image_file() { printf 'probe-artifacts/kms-probe-%s-%s/image.json' "${version}" "$1"; }

# KMS profiles must measure apart (the profile is on the kernel cmdline and in
# the RTMR3 extend), so a debug KMS cannot stand in for a locked one.
for pair in "debug debug-read-only" "debug locked-read-only" "debug-read-only locked-read-only"; do
  read -r left right <<< "${pair}"
  if jq -n -e --slurpfile l "$(kms_measurements "${left}")" --slurpfile r "$(kms_measurements "${right}")" '
    def norm($a): $a | map(ascii_downcase) | sort | unique;
    all(["mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"][];
      norm($l[0].policy["allowed_\(.)"]) == norm($r[0].policy["allowed_\(.)"]))
  ' >/dev/null; then
    fail "KMS ${left} and ${right} have identical MRTD/RTMR0-3; profile cohorts must differ"
  fi
done

# Role separation: the KMS and node images share firmware and kernel (MRTD,
# RTMR0, RTMR1), and are told apart by calimero.role on the cmdline (RTMR2) and
# the role in the boot-time RTMR3 extend. Neither may overlap.
for profile in "${profiles[@]}"; do
  for m in rtmr2 rtmr3; do
    if jq -n -e --slurpfile k "$(kms_measurements "${profile}")" --slurpfile n "${node_policy_file}" \
      --arg p "${profile}" --arg key "allowed_${m}" '
      [$k[0].policy[$key][] | ascii_downcase] as $kv
      | [$n[0].profiles[$p][$key][] | ascii_downcase] as $nv
      | any($nv[]; . as $v | $kv | index($v) != null)
    ' >/dev/null; then
      fail "${profile} ${m} overlaps between the KMS and node roles"
    fi
  done
done

read -r default_binding_hex default_binding_b64 < <(
  python3 -c 'import base64, hashlib; d = hashlib.sha256(b"mero-kms-attest-v1").digest(); print(d.hex(), base64.b64encode(d).decode())'
)
policy_registry_source_path="release-probe+node"

for profile in "${profiles[@]}"; do
  jq -n \
    --arg profile "${profile}" \
    --arg tag "${version}" \
    --arg commit "${PREP_TARGET_COMMIT}" \
    --arg run_id "${GH_RUN_ID}" \
    --arg run_attempt "${GH_RUN_ATTEMPT}" \
    --arg repository "${GH_REPOSITORY}" \
    --arg workflow "${GH_WORKFLOW_NAME}" \
    --arg ref "${GH_REF_NAME}" \
    --arg policy_registry_source_path "${policy_registry_source_path}" \
    --arg default_binding_hex "${default_binding_hex}" \
    --arg default_binding_b64 "${default_binding_b64}" \
    --slurpfile kms "$(kms_measurements "${profile}")" \
    --slurpfile node "${node_policy_file}" \
    '($kms[0].policy) as $k
    | ($node[0].profiles[$profile]) as $n
    | {
      schema_version: 1,
      role: "kms",
      profile: $profile,
      tag: $tag,
      commit_sha: $commit,
      workflow_run_id: $run_id,
      workflow_run_attempt: $run_attempt,
      generated_at: (now | todate),
      source: {
        repository: $repository,
        workflow: $workflow,
        ref: $ref
      },
      policy_registry_entry_path: $policy_registry_source_path,
      measurement_markers: {
        kms_role: "calimero.role=kms",
        node_role: "calimero.role=node",
        node_profile_key: "calimero.profile",
        node_root_hash_key: "calimero.root_hash"
      },
      kms: {
        provider: "mero-kms",
        attest_endpoint: "/attest",
        report_data_layout: {
          bytes_0_31: "nonce",
          bytes_32_63: "binding_or_default_domain_separator"
        },
        default_binding_hex: $default_binding_hex,
        default_binding_b64: $default_binding_b64
      },
      policy: {
        kms_allowed_tcb_statuses: $k.allowed_tcb_statuses,
        kms_allowed_mrtd: $k.allowed_mrtd,
        kms_allowed_rtmr0: $k.allowed_rtmr0,
        kms_allowed_rtmr1: $k.allowed_rtmr1,
        kms_allowed_rtmr2: $k.allowed_rtmr2,
        kms_allowed_rtmr3: $k.allowed_rtmr3,
        node_allowed_tcb_statuses: $n.allowed_tcb_statuses,
        node_allowed_mrtd: $n.allowed_mrtd,
        node_allowed_rtmr0: $n.allowed_rtmr0,
        node_allowed_rtmr1: $n.allowed_rtmr1,
        node_allowed_rtmr2: $n.allowed_rtmr2,
        node_allowed_rtmr3: $n.allowed_rtmr3
      },
      merod_config_path: "tee.kms.attestation"
    }' > "${out}/kms-attestation-policy.${profile}.json"
done
cp "${out}/kms-attestation-policy.locked-read-only.json" "${out}/kms-attestation-policy.json"

# One JSON object per profile: {profile: {image, policy sha256}}.
profiles_json="$(
  for profile in "${profiles[@]}"; do
    jq -n \
      --arg profile "${profile}" \
      --arg sha "$(sha256sum "${out}/kms-attestation-policy.${profile}.json" | awk '{print $1}')" \
      --slurpfile image "$(image_file "${profile}")" \
      '{($profile): {image: $image[0], policy_sha256: $sha}}'
  done | jq -s 'add'
)"

jq -n \
  --arg tag "${version}" \
  --arg run_id "${GH_RUN_ID}" \
  --arg run_attempt "${GH_RUN_ATTEMPT}" \
  --arg kms_tag "${kms_tag}" \
  --arg node_image_tag "${node_tag}" \
  --arg download_base "${download_base}" \
  --arg node_policy_url "${node_policy_url}" \
  --argjson profiles "${profiles_json}" \
  '{
    schema_version: 1,
    tag: $tag,
    workflow_run_id: $run_id,
    workflow_run_attempt: $run_attempt,
    generated_at: (now | todate),
    compatibility: {
      version: $tag,
      roles: {kms: "kms", node: "node"},
      kms_tag: $kms_tag,
      node_image_tag: $node_image_tag,
      kms_policy_url: ($download_base + "/" + $kms_tag + "/kms-attestation-policy.json"),
      kms_policy_sha256: $profiles["locked-read-only"].policy_sha256,
      node_policy_url: $node_policy_url,
      profiles: ($profiles | with_entries(.value = {
        kms_image: .value.image.name,
        kms_image_family: .value.image.family,
        kms_image_project: .value.image.project,
        kms_image_id: .value.image.id,
        kms_role: "kms",
        kms_policy_asset: ("kms-attestation-policy." + .key + ".json"),
        kms_policy_url: ($download_base + "/" + $kms_tag + "/kms-attestation-policy." + .key + ".json"),
        kms_policy_sha256: .value.policy_sha256,
        node_role: "node",
        node_profile: .key,
        node_policy_url: $node_policy_url
      }))
    }
  }' > "${out}/kms-compatibility-map.json"

binaries_json="$(
  while read -r checksum file; do
    jq -nc --arg file "${file}" --arg checksum "${checksum}" '{file: $file, sha256: $checksum}'
  done < "${out}/kms-checksums.txt" | jq -s '.'
)"

jq -n \
  --arg tag "${version}" \
  --arg commit "${PREP_TARGET_COMMIT}" \
  --arg run_id "${GH_RUN_ID}" \
  --arg run_attempt "${GH_RUN_ATTEMPT}" \
  --arg policy_registry_source_path "${policy_registry_source_path}" \
  --argjson binaries "${binaries_json}" \
  --argjson profiles "${profiles_json}" \
  '{
    tag: $tag,
    commit_sha: $commit,
    workflow_run_id: $run_id,
    workflow_run_attempt: $run_attempt,
    generated_at: (now | todate),
    binaries: $binaries,
    images: ($profiles | map_values(.image)),
    verification: {
      kms_attest_endpoint: "/attest",
      report_data_layout: {
        bytes_0_31: "nonce",
        bytes_32_63: "binding_or_default_domain_separator"
      },
      policy_registry_entry_path: $policy_registry_source_path,
      attestation_policy_asset: "kms-attestation-policy.json",
      policy_profile_assets: {
        debug: "kms-attestation-policy.debug.json",
        "debug-read-only": "kms-attestation-policy.debug-read-only.json",
        "locked-read-only": "kms-attestation-policy.locked-read-only.json"
      },
      compatibility_map_asset: "kms-compatibility-map.json",
      rekor: {index_asset: "kms-rekor-index.json"}
    },
    asset_purposes: {
      "kms-checksums.txt": ["operator-required", "auditor-required"],
      "kms-release-manifest.json": ["operator-required", "auditor-required"],
      "kms-attestation-policy.json": ["operator-required", "auditor-required"],
      "kms-attestation-policy.debug.json": ["operator-required", "auditor-required"],
      "kms-attestation-policy.debug-read-only.json": ["operator-required", "auditor-required"],
      "kms-attestation-policy.locked-read-only.json": ["operator-required", "auditor-required"],
      "kms-compatibility-map.json": ["operator-required", "auditor-required"],
      "kms-rekor-index.json": ["auditor-required"],
      "kms-trust-bundle.tar.gz": ["operator-convenience", "auditor-convenience"],
      "kms-binaries-sbom.spdx.json": ["auditor-required"]
    }
  }' > "${out}/kms-release-manifest.json"

bundle_files=(
  kms-checksums.txt
  kms-release-manifest.json
  kms-compatibility-map.json
  kms-attestation-policy.json
  kms-attestation-policy.debug.json
  kms-attestation-policy.debug-read-only.json
  kms-attestation-policy.locked-read-only.json
)
(cd "${out}" && sha256sum "${bundle_files[@]}") > "${out}/MANIFEST.txt"
tar -czf "${out}/kms-trust-bundle.tar.gz" -C "${out}" MANIFEST.txt "${bundle_files[@]}"

allowlist_md() {
  jq -r --arg key "$2" '(.policy[$key] // []) | if length > 0 then map("`" + . + "`") | join("<br>") else "n/a" end' "$1"
}

measurement_table() {
  local role="$1"
  echo "| Profile | MRTD | RTMR0 | RTMR1 | RTMR2 | RTMR3 |"
  echo "|---|---|---|---|---|---|"
  for profile in "${profiles[@]}"; do
    local file="${out}/kms-attestation-policy.${profile}.json"
    local row="| ${profile} |"
    for m in "${metrics[@]}"; do
      row+=" $(allowlist_md "${file}" "${role}_allowed_${m}") |"
    done
    echo "${row}"
  done
}

run_url="https://github.com/${GH_REPOSITORY}/actions/runs/${GH_RUN_ID}"
{
  echo "## mero-kms release ${version}"
  echo ""
  echo "| Field | Value |"
  echo "|---|---|"
  echo "| Tag | \`${kms_tag}\` |"
  echo "| Commit | \`${PREP_TARGET_COMMIT}\` |"
  echo "| Workflow run | [${GH_RUN_ID}](${run_url}) |"
  echo "| Compatible node release | \`${node_tag}\` |"
  echo "| KMS policy (locked-read-only alias) | \`${download_base}/${kms_tag}/kms-attestation-policy.json\` |"
  echo "| Node policy | \`${node_policy_url}\` |"
  echo ""
  echo "### KMS images (GCP, Intel TDX)"
  echo ""
  echo "Each image was booted as a two-replica cluster (bootstrap + attested join) and both replicas' quotes were verified by Intel Trust Authority before its measurements were published."
  echo ""
  echo "| Profile | Image | Family | Project |"
  echo "|---|---|---|---|"
  for profile in "${profiles[@]}"; do
    jq -r --arg p "${profile}" '"| \($p) | `\(.name)` | `\(.family)` | `\(.project)` |"' "$(image_file "${profile}")"
  done
  echo ""
  echo "### KMS measurements (enforced by merod against /attest)"
  echo ""
  measurement_table kms
  echo ""
  echo "### Node measurements (enforced by the KMS for /get-key)"
  echo ""
  measurement_table node
  echo ""
  echo "### Binary archives (SHA-256)"
  echo ""
  echo "| Archive | SHA-256 |"
  echo "|---|---|"
  while read -r checksum archive; do
    echo "| \`${archive}\` | \`${checksum}\` |"
  done < "${out}/kms-checksums.txt"
  echo ""
  echo "### Verification"
  echo ""
  echo "\`\`\`bash"
  echo "scripts/release/verify-kms-release-assets.sh ${kms_tag}"
  echo "scripts/release/verify-release-assets.sh ${version}   # KMS and node releases together"
  echo "\`\`\`"
  echo ""
  echo "### Trust assets"
  echo ""
  echo "| Asset | What it contains |"
  echo "|---|---|"
  echo "| \`kms-attestation-policy.<profile>.json\` | KMS and node allowlists for one profile; merod applies it at \`tee.kms.attestation\` |"
  echo "| \`kms-attestation-policy.json\` | Alias of the locked-read-only policy, the one merod fetches by default |"
  echo "| \`kms-compatibility-map.json\` | KMS release to mero-tee release, per-profile images, policy URLs and hashes |"
  echo "| \`kms-release-manifest.json\` | Release metadata: binaries, images, verification contract |"
  echo "| \`kms-checksums.txt\` | SHA-256 of the binary archives |"
  echo "| \`kms-binaries-sbom.spdx.json\` | SBOM of the binary archives |"
  echo "| \`kms-rekor-index.json\` | Transparency-log entries of the signed assets |"
  echo "| \`kms-trust-bundle.tar.gz\` | \`MANIFEST.txt\`, checksums, manifest, compatibility map and policies, for offline transfer |"
  echo ""
  echo "Every trust asset has Sigstore keyless sidecars (\`.sig\`, \`.pem\`, \`.bundle.json\`) from \`.github/workflows/release-kms.yaml\` on \`master\`."
} > "${out}/release-notes.md"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  cat "${out}/release-notes.md" >> "${GITHUB_STEP_SUMMARY}"
fi
