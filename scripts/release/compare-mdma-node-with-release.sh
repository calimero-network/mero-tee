#!/usr/bin/env bash
# Compare an MDMA-deployed node with mero-tee release assets.
#
# Usage: ./scripts/release/compare-mdma-node-with-release.sh <node_url> [release_version]
#
# Examples:
#   ./compare-mdma-node-with-release.sh http://34.40.15.76:80
#   ./compare-mdma-node-with-release.sh http://34.40.15.76:80 2.2.4
#
# Fetches node's attestation + tee/info, fetches published-mrtds.json and
# release-provenance.json from the release, and compares:
#   - OS image name (does node match release-provenance?)
#   - MRTD, RTMR0-2 (do measurements match published-mrtds?)
#   - RTMR3 (node has no event log; informational only)
#
# Prerequisites: jq, curl. Set GH_TOKEN for private repos.

set -euo pipefail

node_url="${1:-}"
release_version="${2:-}"

if [[ -z "${node_url}" ]]; then
  echo "Usage: $0 <node_url> [release_version]"
  echo ""
  echo "  node_url         Base URL of node admin API (e.g. http://34.40.15.76:80)"
  echo "  release_version  Optional. e.g. 2.2.4. If omitted, attempts to infer from node tee/info."
  echo ""
  exit 1
fi

node_url="${node_url%/}"
repo="${GITHUB_REPOSITORY:-calimero-network/mero-tee}"
api_headers=(-H "Accept: application/vnd.github+json")
if [[ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]]; then
  api_headers+=(-H "Authorization: Bearer ${GH_TOKEN:-${GITHUB_TOKEN}}")
fi

tmp_dir="$(mktemp -d)"
cleanup() { rm -rf "${tmp_dir}"; }
trap cleanup EXIT

echo "=== Fetching node attestation and TEE info ==="
curl -sS --max-time 15 -o "${tmp_dir}/tee-info.json" "${node_url}/admin-api/tee/info" || {
  echo "Failed to fetch ${node_url}/admin-api/tee/info"
  exit 1
}

# Use attestation verifier API for full extraction (ITA + measurements). Falls back to direct node fetch.
verifier_base="${ATTESTATION_VERIFIER_URL:-https://mero-tee.vercel.app}"
if curl -sS --max-time 30 -o "${tmp_dir}/verifier-result.json" \
  -X POST "${verifier_base}/api/verify" \
  -H "Content-Type: application/json" \
  -d "{\"node_url\":\"${node_url}\"}" 2>/dev/null && jq -e '.ita_claims' "${tmp_dir}/verifier-result.json" >/dev/null 2>&1; then
  # Extract from ITA claims (tdx.tdx_mrtd, tdx_rtmr0, etc.)
  jq -r '
    .ita_claims.tdx // {} |
    {
      mrtd: (.tdx_mrtd // ""),
      rtmr0: (.tdx_rtmr0 // ""),
      rtmr1: (.tdx_rtmr1 // ""),
      rtmr2: (.tdx_rtmr2 // ""),
      rtmr3: (.tdx_rtmr3 // "")
    }
  ' "${tmp_dir}/verifier-result.json" > "${tmp_dir}/observed-measurements.json" 2>/dev/null || true
else
  # Fallback: direct node attest + local extraction (requires Python for quote parse)
  nonce="$(openssl rand -hex 32)"
  echo "{\"nonce\":\"${nonce}\"}" > "${tmp_dir}/attest-req.json"
  curl -sS --max-time 20 -o "${tmp_dir}/tee-attest.json" \
    -X POST "${node_url}/admin-api/tee/attest" \
    -H "Content-Type: application/json" \
    -d @"${tmp_dir}/attest-req.json" || true
  echo '{}' > "${tmp_dir}/observed-measurements.json"
fi

# Extract OS image from tee-info if release_version not provided
node_os_image=""
if [[ -f "${tmp_dir}/tee-info.json" ]]; then
  node_os_image="$(jq -r '.data.osImage // .osImage // empty' "${tmp_dir}/tee-info.json")"
  if [[ -z "${release_version}" && -n "${node_os_image}" ]]; then
    # Try to extract version from image name: merotee-ubuntu-questing-25-10-debug-2-2-4 -> 2.2.4
    if [[ "${node_os_image}" =~ -([0-9]+-[0-9]+-[0-9]+)$ ]]; then
      release_version="${BASH_REMATCH[1]//-/.}"
    fi
  fi
fi

if [[ -z "${release_version}" ]]; then
  echo "Could not infer release_version. Provide it as second argument."
  exit 1
fi

node_tag="mero-tee-v${release_version}"
echo ""
echo "=== Fetching release assets (${node_tag}) ==="
curl -sSL -o "${tmp_dir}/published-mrtds.json" \
  "https://github.com/${repo}/releases/download/${node_tag}/published-mrtds.json" || {
  echo "Failed to fetch published-mrtds.json for ${node_tag}"
  exit 1
}

curl -sSL -o "${tmp_dir}/release-provenance.json" \
  "https://github.com/${repo}/releases/download/${node_tag}/release-provenance.json" || {
  echo "Failed to fetch release-provenance.json for ${node_tag}"
  exit 1
}

# Extract measurements from attest response (quote -> ITA or local decode)
# For simplicity we use the attest response shape. The verifier normalizes it.
# We need MRTD, RTMR0-2 from the quote/ITA. Use Python if available, else jq on raw.
observed_file="${tmp_dir}/observed-measurements.json"
if ! jq -e '.mrtd // .rtmr0' "${observed_file}" >/dev/null 2>&1; then
  echo "Warning: Could not extract measurements (verifier API unreachable or node not reachable from verifier)."
  echo "  Ensure node has public IP and attestation verifier can reach it."
  echo ""
fi

echo ""
echo "=== Comparison: MDMA node vs mero-tee release ${node_tag} ==="
echo ""

# 1. Image comparison
echo "## Image"
echo "Node OS image:  ${node_os_image:-n/a}"
release_images="$(jq -r '
  .profiles | to_entries[] | "  \(.key): \(.value.image.name // .value.image_name // "n/a")"
' "${tmp_dir}/release-provenance.json" 2>/dev/null || echo "  (release-provenance has no profiles)")
"
if [[ -n "${release_images}" ]]; then
  echo "Release images:"
  echo "${release_images}"
  if [[ -n "${node_os_image}" ]]; then
    match="false"
    for profile in debug debug-read-only locked-read-only; do
      expected="$(jq -r --arg p "${profile}" '.profiles[$p].image.name // .profiles[$p].image_name // empty' "${tmp_dir}/release-provenance.json" 2>/dev/null)"
      if [[ "${expected}" == "${node_os_image}" ]]; then
        echo "  ✓ Node image matches release profile: ${profile}"
        match="true"
        break
      fi
    done
    if [[ "${match}" == "false" ]]; then
      echo "  ✗ Node image does not match any release profile image"
    fi
  fi
fi
echo ""

# 2. Measurement comparison
echo "## Measurements (MRTD, RTMR0-2)"
obs_mrtd="$(jq -r '.mrtd // empty' "${observed_file}" | tr -d ' \n' | tr '[:upper:]' '[:lower:]')"
obs_rtmr0="$(jq -r '.rtmr0 // empty' "${observed_file}" | tr -d ' \n' | tr '[:upper:]' '[:lower:]')"
obs_rtmr1="$(jq -r '.rtmr1 // empty' "${observed_file}" | tr -d ' \n' | tr '[:upper:]' '[:lower:]')"
obs_rtmr2="$(jq -r '.rtmr2 // empty' "${observed_file}" | tr -d ' \n' | tr '[:upper:]' '[:lower:]')"

check_measurement() {
  local name="$1"
  local observed="$2"
  local profile="$3"
  local key="$4"
  local expected
  expected="$(jq -r --arg p "${profile}" --arg k "${key}" '.profiles[$p][$k][0] // empty' "${tmp_dir}/published-mrtds.json" 2>/dev/null | tr -d ' \n' | tr '[:upper:]' '[:lower:]')"
  if [[ -z "${observed}" ]]; then
    echo "  ${name}: (could not extract from node)"
    return
  fi
  if [[ -z "${expected}" ]]; then
    echo "  ${name}: observed=${observed:0:24}… (no expected in policy)"
    return
  fi
  if [[ "${observed}" == "${expected}" ]]; then
    echo "  ${name}: ✓ Match (${profile})"
  else
    echo "  ${name}: ✗ Mismatch"
    echo "      Observed: ${observed:0:48}…"
    echo "      Expected: ${expected:0:48}…"
  fi
}

# Infer profile from MRTD match
matched_profile=""
for profile in debug debug-read-only locked-read-only; do
  exp_mrtd="$(jq -r --arg p "${profile}" '.profiles[$p].allowed_mrtd[0] // empty' "${tmp_dir}/published-mrtds.json" 2>/dev/null | tr -d ' \n' | tr '[:upper:]' '[:lower:]')"
  if [[ -n "${exp_mrtd}" && "${obs_mrtd}" == "${exp_mrtd}" ]]; then
    matched_profile="${profile}"
    break
  fi
done

if [[ -z "${matched_profile}" ]]; then
  matched_profile="debug"
fi

check_measurement "MRTD"  "${obs_mrtd}"  "${matched_profile}" "allowed_mrtd"
check_measurement "RTMR0" "${obs_rtmr0}" "${matched_profile}" "allowed_rtmr0"
check_measurement "RTMR1" "${obs_rtmr1}" "${matched_profile}" "allowed_rtmr1"
check_measurement "RTMR2" "${obs_rtmr2}" "${matched_profile}" "allowed_rtmr2"

echo ""
echo "Profile inferred from MRTD: ${matched_profile}"
echo ""
echo "For full ITA verification and RTMR allowlist check, use the attestation verifier:"
echo "  https://mero-tee.vercel.app/mero-tee?node_url=${node_url}&release_tag=${node_tag}"
