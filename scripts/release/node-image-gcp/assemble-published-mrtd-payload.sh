#!/usr/bin/env bash
set -euo pipefail

# Validate profile artifacts and assemble published MRTD/provenance outputs.
# Inputs: RELEASE_VERSION and generated files in artifacts/.
# Produces: published-mrtds.json, release-provenance.json, release-notes.md, checksums.

release_tag="${RELEASE_VERSION:?RELEASE_VERSION is required}"

validate_mrtd_file() {
  local file_path="$1"
  local label="$2"
  local mrtd
  mrtd="$(jq -r '.mrtd // empty' "${file_path}" | tr '[:upper:]' '[:lower:]')"
  mrtd="${mrtd#0x}"
  if [[ ! "${mrtd}" =~ ^[a-f0-9]{96}$ ]]; then
    echo "Invalid MRTD for ${label}: expected 96 hex characters, got '${mrtd}'."
    exit 1
  fi
  local tmp_path
  tmp_path="$(mktemp)"
  jq --arg mrtd "${mrtd}" '.mrtd = $mrtd' "${file_path}" > "${tmp_path}"
  mv "${tmp_path}" "${file_path}"
}

validate_provenance_file() {
  local file_path="$1"
  local label="$2"
  jq -e '
    .external_verification.status == "performed"
    and (.external_verification.mrtd | type == "string")
    and (.external_verification.mrtd | test("^[A-Fa-f0-9]{96}$"))
  ' "${file_path}" >/dev/null || {
    echo "Invalid external verification block in ${label}: expected status=performed and a 96-char hex MRTD."
    exit 1
  }
}

validate_measurement_policy_file() {
  local file_path="$1"
  local label="$2"
  jq -e '
    .schema_version == 1
    and (.policy.allowed_mrtd | type == "array" and length > 0)
    and (.policy.allowed_rtmr0 | type == "array" and length > 0)
    and (.policy.allowed_rtmr1 | type == "array" and length > 0)
    and (.policy.allowed_rtmr2 | type == "array" and length > 0)
    and (.policy.allowed_rtmr3 | type == "array" and length > 0)
  ' "${file_path}" >/dev/null || {
    echo "Invalid measurement policy candidate in ${label}"
    exit 1
  }
}

ensure_policy_matches_mrtd() {
  local mrtd_file="$1"
  local policy_file="$2"
  local label="$3"
  local mrtd_value policy_mrtd

  mrtd_value="$(jq -r '.mrtd // empty' "${mrtd_file}" | tr '[:upper:]' '[:lower:]')"
  mrtd_value="${mrtd_value#0x}"
  policy_mrtd="$(jq -r '.policy.allowed_mrtd[0] // empty' "${policy_file}" | tr '[:upper:]' '[:lower:]')"
  policy_mrtd="${policy_mrtd#0x}"

  if [[ -z "${policy_mrtd}" || "${policy_mrtd}" != "${mrtd_value}" ]]; then
    echo "Measurement policy mismatch for ${label}: first allowed_mrtd='${policy_mrtd}' but mrtd='${mrtd_value}'"
    exit 1
  fi
}

if [[ ! -f artifacts/mrtd-debug.json ]]; then
  echo "Missing artifacts/mrtd-debug.json"
  ls -la artifacts || true
  exit 1
fi
if [[ ! -f artifacts/mrtd-debug-read-only.json ]]; then
  echo "Missing artifacts/mrtd-debug-read-only.json"
  ls -la artifacts || true
  exit 1
fi
if [[ ! -f artifacts/mrtd-locked-read-only.json ]]; then
  echo "Missing artifacts/mrtd-locked-read-only.json"
  ls -la artifacts || true
  exit 1
fi
if [[ ! -f artifacts/profile-provenance-debug.json ]]; then
  echo "Missing artifacts/profile-provenance-debug.json"
  ls -la artifacts || true
  exit 1
fi
if [[ ! -f artifacts/profile-provenance-debug-read-only.json ]]; then
  echo "Missing artifacts/profile-provenance-debug-read-only.json"
  ls -la artifacts || true
  exit 1
fi
if [[ ! -f artifacts/profile-provenance-locked-read-only.json ]]; then
  echo "Missing artifacts/profile-provenance-locked-read-only.json"
  ls -la artifacts || true
  exit 1
fi
if [[ ! -f artifacts/measurement-policy-candidates-debug.json ]]; then
  echo "Missing artifacts/measurement-policy-candidates-debug.json"
  ls -la artifacts || true
  exit 1
fi
if [[ ! -f artifacts/measurement-policy-candidates-debug-read-only.json ]]; then
  echo "Missing artifacts/measurement-policy-candidates-debug-read-only.json"
  ls -la artifacts || true
  exit 1
fi
if [[ ! -f artifacts/measurement-policy-candidates-locked-read-only.json ]]; then
  echo "Missing artifacts/measurement-policy-candidates-locked-read-only.json"
  ls -la artifacts || true
  exit 1
fi

validate_mrtd_file "artifacts/mrtd-debug.json" "debug"
validate_mrtd_file "artifacts/mrtd-debug-read-only.json" "debug-read-only"
validate_mrtd_file "artifacts/mrtd-locked-read-only.json" "locked-read-only"
validate_provenance_file "artifacts/profile-provenance-debug.json" "profile-provenance-debug.json"
validate_provenance_file "artifacts/profile-provenance-debug-read-only.json" "profile-provenance-debug-read-only.json"
validate_provenance_file "artifacts/profile-provenance-locked-read-only.json" "profile-provenance-locked-read-only.json"
validate_measurement_policy_file "artifacts/measurement-policy-candidates-debug.json" "measurement-policy-candidates-debug.json"
validate_measurement_policy_file "artifacts/measurement-policy-candidates-debug-read-only.json" "measurement-policy-candidates-debug-read-only.json"
validate_measurement_policy_file "artifacts/measurement-policy-candidates-locked-read-only.json" "measurement-policy-candidates-locked-read-only.json"
ensure_policy_matches_mrtd "artifacts/mrtd-debug.json" "artifacts/measurement-policy-candidates-debug.json" "debug"
ensure_policy_matches_mrtd "artifacts/mrtd-debug-read-only.json" "artifacts/measurement-policy-candidates-debug-read-only.json" "debug-read-only"
ensure_policy_matches_mrtd "artifacts/mrtd-locked-read-only.json" "artifacts/measurement-policy-candidates-locked-read-only.json" "locked-read-only"

# MRTD is firmware-only (TDVF) per GCP TDX docs; identical for all profiles.
# RTMR[2] includes kernel cmdline; we inject calimero.role=node + calimero.profile=<profile> so each profile
# produces different RTMRs. At least one RTMR must differ so KMS can distinguish images.
debug_rtmr0="$(jq -r '.policy.allowed_rtmr0[0] // empty' artifacts/measurement-policy-candidates-debug.json | tr '[:upper:]' '[:lower:]')"
debug_ro_rtmr0="$(jq -r '.policy.allowed_rtmr0[0] // empty' artifacts/measurement-policy-candidates-debug-read-only.json | tr '[:upper:]' '[:lower:]')"
locked_ro_rtmr0="$(jq -r '.policy.allowed_rtmr0[0] // empty' artifacts/measurement-policy-candidates-locked-read-only.json | tr '[:upper:]' '[:lower:]')"
debug_rtmr2="$(jq -r '.policy.allowed_rtmr2[0] // empty' artifacts/measurement-policy-candidates-debug.json | tr '[:upper:]' '[:lower:]')"
debug_ro_rtmr2="$(jq -r '.policy.allowed_rtmr2[0] // empty' artifacts/measurement-policy-candidates-debug-read-only.json | tr '[:upper:]' '[:lower:]')"
locked_ro_rtmr2="$(jq -r '.policy.allowed_rtmr2[0] // empty' artifacts/measurement-policy-candidates-locked-read-only.json | tr '[:upper:]' '[:lower:]')"
debug_rtmr3="$(jq -r '.policy.allowed_rtmr3[0] // empty' artifacts/measurement-policy-candidates-debug.json | tr '[:upper:]' '[:lower:]')"
debug_ro_rtmr3="$(jq -r '.policy.allowed_rtmr3[0] // empty' artifacts/measurement-policy-candidates-debug-read-only.json | tr '[:upper:]' '[:lower:]')"
locked_ro_rtmr3="$(jq -r '.policy.allowed_rtmr3[0] // empty' artifacts/measurement-policy-candidates-locked-read-only.json | tr '[:upper:]' '[:lower:]')"
profiles_differ=false
if [[ -n "${debug_rtmr2}" && -n "${debug_ro_rtmr2}" && -n "${locked_ro_rtmr2}" ]]; then
  if [[ "${debug_rtmr2}" != "${debug_ro_rtmr2}" || "${debug_ro_rtmr2}" != "${locked_ro_rtmr2}" ]]; then
    profiles_differ=true
  fi
fi
if [[ "${profiles_differ}" != "true" && -n "${debug_rtmr3}" && -n "${debug_ro_rtmr3}" && -n "${locked_ro_rtmr3}" ]]; then
  if [[ "${debug_rtmr3}" != "${debug_ro_rtmr3}" || "${debug_ro_rtmr3}" != "${locked_ro_rtmr3}" ]]; then
    profiles_differ=true
  fi
fi
if [[ "${profiles_differ}" != "true" && -n "${debug_rtmr0}" && -n "${debug_ro_rtmr0}" && -n "${locked_ro_rtmr0}" ]]; then
  if [[ "${debug_rtmr0}" != "${debug_ro_rtmr0}" || "${debug_ro_rtmr0}" != "${locked_ro_rtmr0}" ]]; then
    profiles_differ=true
  fi
fi
if [[ "${profiles_differ}" != "true" ]]; then
  echo "::error::All three profiles have identical RTMR0/RTMR2/RTMR3. Profiles must produce different measurements (calimero.role+calimero.profile+root_hash in RTMR[2], RTMR3 extend at boot)."
  echo "  RTMR2: debug=${debug_rtmr2:0:24}... debug-ro=${debug_ro_rtmr2:0:24}... locked-ro=${locked_ro_rtmr2:0:24}..."
  echo "  RTMR3: debug=${debug_rtmr3:0:24}... (empty if kernel <6.16)"
  exit 1
fi

jq -n \
  --arg tag "${release_tag}" \
  --slurpfile debug artifacts/mrtd-debug.json \
  --slurpfile debug_ro artifacts/mrtd-debug-read-only.json \
  --slurpfile locked_ro artifacts/mrtd-locked-read-only.json \
  --slurpfile debug_policy artifacts/measurement-policy-candidates-debug.json \
  --slurpfile debug_ro_policy artifacts/measurement-policy-candidates-debug-read-only.json \
  --slurpfile locked_ro_policy artifacts/measurement-policy-candidates-locked-read-only.json \
  '{
    role: "node",
    tag: $tag,
    generated_at: (now | todate),
    measurement_markers: {
      role: "calimero.role=node",
      profile_key: "calimero.profile",
      root_hash_key: "calimero.root_hash"
    },
    profiles: {
      debug: (
        $debug[0] + {
          allowed_mrtd: ($debug_policy[0].policy.allowed_mrtd // []),
          allowed_rtmr0: ($debug_policy[0].policy.allowed_rtmr0 // []),
          allowed_rtmr1: ($debug_policy[0].policy.allowed_rtmr1 // []),
          allowed_rtmr2: ($debug_policy[0].policy.allowed_rtmr2 // []),
          allowed_rtmr3: ($debug_policy[0].policy.allowed_rtmr3 // []),
          allowed_tcb_statuses: ($debug_policy[0].policy.allowed_tcb_statuses // [])
        }
      ),
      "debug-read-only": (
        $debug_ro[0] + {
          allowed_mrtd: ($debug_ro_policy[0].policy.allowed_mrtd // []),
          allowed_rtmr0: ($debug_ro_policy[0].policy.allowed_rtmr0 // []),
          allowed_rtmr1: ($debug_ro_policy[0].policy.allowed_rtmr1 // []),
          allowed_rtmr2: ($debug_ro_policy[0].policy.allowed_rtmr2 // []),
          allowed_rtmr3: ($debug_ro_policy[0].policy.allowed_rtmr3 // []),
          allowed_tcb_statuses: ($debug_ro_policy[0].policy.allowed_tcb_statuses // [])
        }
      ),
      "locked-read-only": (
        $locked_ro[0] + {
          allowed_mrtd: ($locked_ro_policy[0].policy.allowed_mrtd // []),
          allowed_rtmr0: ($locked_ro_policy[0].policy.allowed_rtmr0 // []),
          allowed_rtmr1: ($locked_ro_policy[0].policy.allowed_rtmr1 // []),
          allowed_rtmr2: ($locked_ro_policy[0].policy.allowed_rtmr2 // []),
          allowed_rtmr3: ($locked_ro_policy[0].policy.allowed_rtmr3 // []),
          allowed_tcb_statuses: ($locked_ro_policy[0].policy.allowed_tcb_statuses // [])
        }
      )
    }
  }' > artifacts/published-mrtds.json

jq -e '
  .role == "node" and
  (.profiles.debug.allowed_tcb_statuses | type == "array" and length > 0) and
  (.profiles.debug.allowed_mrtd | type == "array" and length > 0) and
  (.profiles.debug.allowed_rtmr0 | type == "array" and length > 0) and
  (.profiles.debug.allowed_rtmr1 | type == "array" and length > 0) and
  (.profiles.debug.allowed_rtmr2 | type == "array" and length > 0) and
  (.profiles.debug.allowed_rtmr3 | type == "array" and length > 0) and
  (.profiles["debug-read-only"].allowed_tcb_statuses | type == "array" and length > 0) and
  (.profiles["debug-read-only"].allowed_mrtd | type == "array" and length > 0) and
  (.profiles["debug-read-only"].allowed_rtmr0 | type == "array" and length > 0) and
  (.profiles["debug-read-only"].allowed_rtmr1 | type == "array" and length > 0) and
  (.profiles["debug-read-only"].allowed_rtmr2 | type == "array" and length > 0) and
  (.profiles["debug-read-only"].allowed_rtmr3 | type == "array" and length > 0) and
  (.profiles["locked-read-only"].allowed_tcb_statuses | type == "array" and length > 0) and
  (.profiles["locked-read-only"].allowed_mrtd | type == "array" and length > 0) and
  (.profiles["locked-read-only"].allowed_rtmr0 | type == "array" and length > 0) and
  (.profiles["locked-read-only"].allowed_rtmr1 | type == "array" and length > 0) and
  (.profiles["locked-read-only"].allowed_rtmr2 | type == "array" and length > 0) and
  (.profiles["locked-read-only"].allowed_rtmr3 | type == "array" and length > 0)
' artifacts/published-mrtds.json >/dev/null

version="${release_tag}"
kms_tag="mero-kms-v${version}"
node_image_tag="mero-tee-v${version}"
kms_policy_url="https://github.com/${GITHUB_REPOSITORY}/releases/download/${kms_tag}/kms-phala-attestation-policy.json"
node_policy_url="https://github.com/${GITHUB_REPOSITORY}/releases/download/${node_image_tag}/published-mrtds.json"

jq -n \
  --arg tag "${release_tag}" \
  --arg commit "${GITHUB_SHA}" \
  --arg run_id "${GITHUB_RUN_ID}" \
  --arg run_attempt "${GITHUB_RUN_ATTEMPT}" \
  --arg version "${version}" \
  --arg kms_tag "${kms_tag}" \
  --arg node_image_tag "${node_image_tag}" \
  --arg kms_policy_url "${kms_policy_url}" \
  --arg node_policy_url "${node_policy_url}" \
  --slurpfile debug artifacts/profile-provenance-debug.json \
  --slurpfile debug_ro artifacts/profile-provenance-debug-read-only.json \
  --slurpfile locked_ro artifacts/profile-provenance-locked-read-only.json \
  --slurpfile mrtds artifacts/published-mrtds.json \
  '{
    role: "node",
    tag: $tag,
    commit_sha: $commit,
    workflow_run_id: $run_id,
    workflow_run_attempt: $run_attempt,
    generated_at: (now | todate),
    compatibility: {
      version: $version,
      kms_tag: $kms_tag,
      node_image_tag: $node_image_tag,
      kms_policy_url: $kms_policy_url,
      node_policy_url: $node_policy_url
    },
    profiles: {
      debug: $debug[0],
      "debug-read-only": $debug_ro[0],
      "locked-read-only": $locked_ro[0]
    },
    mrtds: $mrtds[0],
    measurement_policy: $mrtds[0],
    asset_purposes: {
      "published-mrtds.json": ["operator-required", "auditor-required"],
      "release-provenance.json": ["auditor-required"],
      "node-image-gcp-release-sbom.spdx.json": ["auditor-required"],
      "node-image-gcp-checksums.txt": ["operator-required", "auditor-required"]
    }
  }' > artifacts/release-provenance.json

sbom_dir="$(mktemp -d)"
cp artifacts/published-mrtds.json artifacts/release-provenance.json "${sbom_dir}/"
syft "dir:${sbom_dir}" -o "spdx-json=artifacts/node-image-gcp-release-sbom.spdx.json"
rm -rf "${sbom_dir}"

sha256sum \
  artifacts/published-mrtds.json \
  artifacts/release-provenance.json \
  artifacts/node-image-gcp-release-sbom.spdx.json \
  | sed 's#  artifacts/#  #' \
  > artifacts/node-image-gcp-checksums.txt

format_profile_allowlist_md() {
  local profile="$1"
  local key="$2"
  jq -r --arg profile "${profile}" --arg key "${key}" '
    (.profiles[$profile][$key] // [])
    | if (type == "array" and length > 0) then
        map("`" + tostring + "`") | join("<br>")
      else
        "n/a"
      end
  ' artifacts/published-mrtds.json
}

debug_mrtd="$(format_profile_allowlist_md "debug" "allowed_mrtd")"
debug_ro_mrtd="$(format_profile_allowlist_md "debug-read-only" "allowed_mrtd")"
locked_ro_mrtd="$(format_profile_allowlist_md "locked-read-only" "allowed_mrtd")"
debug_rtmr0="$(format_profile_allowlist_md "debug" "allowed_rtmr0")"
debug_rtmr1="$(format_profile_allowlist_md "debug" "allowed_rtmr1")"
debug_rtmr2="$(format_profile_allowlist_md "debug" "allowed_rtmr2")"
debug_rtmr3="$(format_profile_allowlist_md "debug" "allowed_rtmr3")"
debug_ro_rtmr0="$(format_profile_allowlist_md "debug-read-only" "allowed_rtmr0")"
debug_ro_rtmr1="$(format_profile_allowlist_md "debug-read-only" "allowed_rtmr1")"
debug_ro_rtmr2="$(format_profile_allowlist_md "debug-read-only" "allowed_rtmr2")"
debug_ro_rtmr3="$(format_profile_allowlist_md "debug-read-only" "allowed_rtmr3")"
locked_ro_rtmr0="$(format_profile_allowlist_md "locked-read-only" "allowed_rtmr0")"
locked_ro_rtmr1="$(format_profile_allowlist_md "locked-read-only" "allowed_rtmr1")"
locked_ro_rtmr2="$(format_profile_allowlist_md "locked-read-only" "allowed_rtmr2")"
locked_ro_rtmr3="$(format_profile_allowlist_md "locked-read-only" "allowed_rtmr3")"

debug_mrtd_preview="$(jq -r '.profiles.debug.allowed_mrtd[0] // "n/a"' artifacts/published-mrtds.json)"
debug_ro_mrtd_preview="$(jq -r '.profiles["debug-read-only"].allowed_mrtd[0] // "n/a"' artifacts/published-mrtds.json)"
locked_ro_mrtd_preview="$(jq -r '.profiles["locked-read-only"].allowed_mrtd[0] // "n/a"' artifacts/published-mrtds.json)"
debug_rtmr0_preview="$(jq -r '.profiles.debug.allowed_rtmr0[0] // "n/a"' artifacts/published-mrtds.json)"
debug_rtmr1_preview="$(jq -r '.profiles.debug.allowed_rtmr1[0] // "n/a"' artifacts/published-mrtds.json)"
debug_rtmr2_preview="$(jq -r '.profiles.debug.allowed_rtmr2[0] // "n/a"' artifacts/published-mrtds.json)"
debug_rtmr3_preview="$(jq -r '.profiles.debug.allowed_rtmr3[0] // "n/a"' artifacts/published-mrtds.json)"
debug_ro_rtmr0_preview="$(jq -r '.profiles["debug-read-only"].allowed_rtmr0[0] // "n/a"' artifacts/published-mrtds.json)"
debug_ro_rtmr1_preview="$(jq -r '.profiles["debug-read-only"].allowed_rtmr1[0] // "n/a"' artifacts/published-mrtds.json)"
debug_ro_rtmr2_preview="$(jq -r '.profiles["debug-read-only"].allowed_rtmr2[0] // "n/a"' artifacts/published-mrtds.json)"
debug_ro_rtmr3_preview="$(jq -r '.profiles["debug-read-only"].allowed_rtmr3[0] // "n/a"' artifacts/published-mrtds.json)"
locked_ro_rtmr0_preview="$(jq -r '.profiles["locked-read-only"].allowed_rtmr0[0] // "n/a"' artifacts/published-mrtds.json)"
locked_ro_rtmr1_preview="$(jq -r '.profiles["locked-read-only"].allowed_rtmr1[0] // "n/a"' artifacts/published-mrtds.json)"
locked_ro_rtmr2_preview="$(jq -r '.profiles["locked-read-only"].allowed_rtmr2[0] // "n/a"' artifacts/published-mrtds.json)"
locked_ro_rtmr3_preview="$(jq -r '.profiles["locked-read-only"].allowed_rtmr3[0] // "n/a"' artifacts/published-mrtds.json)"

run_url="https://github.com/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"

{
  echo "## mero-tee release ${release_tag}"
  echo ""
  echo "### Release metadata"
  echo ""
  echo "| Field | Value |"
  echo "|---|---|"
  echo "| Tag | \`mero-tee-v${release_tag}\` |"
  echo "| Commit | \`${GITHUB_SHA}\` |"
  echo "| Workflow run | [${GITHUB_RUN_ID}](${run_url}) |"
  echo "| Checksums | \`node-image-gcp-checksums.txt\` |"
  echo ""
  echo "### Compatibility map"
  echo ""
  echo "| Field | Value |"
  echo "|---|---|"
  echo "| KMS release tag | \`${kms_tag}\` |"
  echo "| merod release tag | \`${node_image_tag}\` |"
  echo "| KMS policy URL | \`${kms_policy_url}\` |"
  echo "| Node policy URL | \`${node_policy_url}\` |"
  echo ""
  echo "### Profile measurements"
  echo ""
  echo "| Profile | MRTD |"
  echo "|---|---|"
  echo "| debug | ${debug_mrtd} |"
  echo "| debug-read-only | ${debug_ro_mrtd} |"
  echo "| locked-read-only | ${locked_ro_mrtd} |"
  echo ""
  echo "| Profile | RTMR0 | RTMR1 | RTMR2 | RTMR3 |"
  echo "|---|---|---|---|---|"
  echo "| debug | ${debug_rtmr0} | ${debug_rtmr1} | ${debug_rtmr2} | ${debug_rtmr3} |"
  echo "| debug-read-only | ${debug_ro_rtmr0} | ${debug_ro_rtmr1} | ${debug_ro_rtmr2} | ${debug_ro_rtmr3} |"
  echo "| locked-read-only | ${locked_ro_rtmr0} | ${locked_ro_rtmr1} | ${locked_ro_rtmr2} | ${locked_ro_rtmr3} |"
  echo ""
  echo "### Full profile allowlists (all MRTD/RTMR arrays)"
  echo ""
  echo "#### Profile: debug"
  echo "\`\`\`json"
  jq '.profiles.debug | {
    mrtd,
    allowed_tcb_statuses,
    allowed_mrtd,
    allowed_rtmr0,
    allowed_rtmr1,
    allowed_rtmr2,
    allowed_rtmr3
  }' artifacts/published-mrtds.json
  echo "\`\`\`"
  echo ""
  echo "#### Profile: debug-read-only"
  echo "\`\`\`json"
  jq '.profiles["debug-read-only"] | {
    mrtd,
    allowed_tcb_statuses,
    allowed_mrtd,
    allowed_rtmr0,
    allowed_rtmr1,
    allowed_rtmr2,
    allowed_rtmr3
  }' artifacts/published-mrtds.json
  echo "\`\`\`"
  echo ""
  echo "#### Profile: locked-read-only"
  echo "\`\`\`json"
  jq '.profiles["locked-read-only"] | {
    mrtd,
    allowed_tcb_statuses,
    allowed_mrtd,
    allowed_rtmr0,
    allowed_rtmr1,
    allowed_rtmr2,
    allowed_rtmr3
  }' artifacts/published-mrtds.json
  echo "\`\`\`"
  echo ""
  echo "### Verification commands"
  echo ""
  echo "**Quick verify (operator):**"
  echo "\`\`\`bash"
  echo "scripts/release/verify-node-image-gcp-release-assets.sh mero-tee-v${release_tag}"
  echo "\`\`\`"
  echo ""
  echo "**Full audit (all release classes):**"
  echo "\`\`\`bash"
  echo "scripts/release/verify-release-assets.sh ${release_tag}"
  echo "\`\`\`"
  echo ""
  echo "### Trust assets (detailed)"
  echo ""
  echo "| Asset | What it contains | Why operators need it |"
  echo "|---|---|---|"
  echo "| \`published-mrtds.json\` | Profile measurement policy (MRTD/RTMR allowlists) | Runtime quote measurement validation baseline |"
  echo "| \`release-provenance.json\` | Build/attestation metadata, compatibility references, and profile verification records | Audit and release-governance evidence |"
  echo "| \`node-image-gcp-release-sbom.spdx.json\` | SBOM for release trust artifacts | Supply-chain and compliance review |"
  echo "| \`node-image-gcp-checksums.txt\` | SHA-256 for release trust artifacts | Integrity verification before policy usage |"
  echo "| \`*.sig / *.pem\` | Sigstore keyless signatures/certificates | Verifiable provenance and authenticity checks |"
  echo ""
  echo "KMS-side profile policies for the matching release are linked via:"
  echo "- \`${kms_policy_url}\` (default/locked policy alias)"
  echo "- Profile-specific URLs in \`kms-phala-compatibility-map.json\` under \`.compatibility.profiles.*.kms_policy_url\`"
} > artifacts/release-notes.md

{
  echo "## Published MRTDs"
  echo ""
  echo "- Tag: ${release_tag}"
  echo "- Debug MRTD: ${debug_mrtd_preview}"
  echo "- Debug read-only MRTD: ${debug_ro_mrtd_preview}"
  echo "- Locked read-only MRTD: ${locked_ro_mrtd_preview}"
  echo ""
  echo "### RTMRs"
  echo "| Profile | RTMR0 | RTMR1 | RTMR2 | RTMR3 |"
  echo "|---|---|---|---|---|"
  echo "| debug | ${debug_rtmr0_preview} | ${debug_rtmr1_preview} | ${debug_rtmr2_preview} | ${debug_rtmr3_preview} |"
  echo "| debug-read-only | ${debug_ro_rtmr0_preview} | ${debug_ro_rtmr1_preview} | ${debug_ro_rtmr2_preview} | ${debug_ro_rtmr3_preview} |"
  echo "| locked-read-only | ${locked_ro_rtmr0_preview} | ${locked_ro_rtmr1_preview} | ${locked_ro_rtmr2_preview} | ${locked_ro_rtmr3_preview} |"
} >> "${GITHUB_STEP_SUMMARY}"
