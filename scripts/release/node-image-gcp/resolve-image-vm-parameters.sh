#!/usr/bin/env bash
set -euo pipefail

# Resolve image, VM, firewall, and artifact parameters for attestation jobs.
# Inputs: PROFILE plus optional GCP_* overrides and versions.json.
# Outputs (GITHUB_OUTPUT): image/VM/firewall fields consumed by later jobs.

if [[ -z "${PROFILE:-}" ]]; then
  echo "::error::PROFILE is required"
  exit 1
fi

if [[ -z "${GITHUB_OUTPUT:-}" ]]; then
  echo "::error::GITHUB_OUTPUT is required"
  exit 1
fi

echo "Resolving image and VM parameters..."
profile="${PROFILE}"
image_version="$(jq -r '.imageVersion // empty' versions.json 2>/dev/null || true)"
if [[ -z "${image_version}" ]]; then
  echo "::error::Could not read imageVersion from versions.json (missing file or key)."
  exit 1
fi
packer_vars_file="ubuntu-x86.pkrvars.hcl"
if [[ ! -f "${packer_vars_file}" ]]; then
  echo "::error::Missing packer vars file: ${packer_vars_file}"
  exit 1
fi

# Always x86; architecture in image name omitted (we only deploy on Intel TDX)
cpu_architecture="x86"
image_name="merotee-ubuntu-questing-25-10-${profile}-${image_version//./-}"
image_project="${PACKER_GCP_PROJECT_ID:-${GOOGLE_CLOUD_PROJECT:-${CLOUDSDK_CORE_PROJECT:-calimero-p2p-development}}}"

# Attestation VM project: same as Calimero Cloud MDMA (cloud-486420) by default so
# published-mrtds.json matches dispatcher nodes. Set GCP_ATTESTATION_PROJECT_ID to override
# (e.g. image_project for legacy Packer-only attestation).
vm_project="${GCP_ATTESTATION_PROJECT_ID:-cloud-486420}"
vm_zone="${GCP_ATTESTATION_ZONE:-${PACKER_GCP_ZONE:-europe-west4-a}}"
# Do not reuse Packer subnet in a different project (subnet URLs are project-scoped).
vm_subnetwork="${GCP_ATTESTATION_SUBNETWORK:-}"
if [[ -z "${vm_subnetwork}" ]] && [[ "${vm_project}" == "${image_project}" ]]; then
  vm_subnetwork="${PACKER_GCP_SUBNETWORK:-}"
fi
vm_machine_type="${GCP_ATTESTATION_MACHINE_TYPE:-c3-standard-4}"
vm_region="${vm_zone%-[a-z]}"
admin_api_port="${GCP_ATTESTATION_ADMIN_API_PORT:-80}"

# Auto-discover subnetwork if not set (same logic as Validate GCP compute access)
if [[ -z "${vm_subnetwork}" ]]; then
  echo "Subnetwork not set; auto-discovering in region ${vm_region}..."
  vm_subnetwork="$(gcloud compute networks subnets list \
    --project "${vm_project}" \
    --regions "${vm_region}" \
    --format="value(name)" \
    --limit=1 2>/dev/null | head -n1 || true)"
fi
if [[ -z "${vm_subnetwork}" ]]; then
  echo "::error::No subnetwork for attestation VM in project '${vm_project}' (region ${vm_region}). Set GCP_ATTESTATION_SUBNETWORK or ensure this project has a subnet (Packer subnet is only inherited when vm_project == image_project)."
  exit 1
fi
echo "Using attestation vm_project=${vm_project} (image_project=${image_project}), subnetwork: ${vm_subnetwork}"
vm_subnetwork_name="${vm_subnetwork##*/}"
vm_network_uri="$(gcloud compute networks subnets describe "${vm_subnetwork_name}" \
  --project "${vm_project}" \
  --region "${vm_region}" \
  --format='value(network)' 2>/dev/null || true)"
if [[ -z "${vm_network_uri}" ]]; then
  echo "::error::Unable to resolve network for subnetwork '${vm_subnetwork_name}' in region '${vm_region}' (project '${vm_project}')."
  exit 1
fi
vm_network="${vm_network_uri##*/}"

firewall_tag="tee-attest-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
firewall_tag="${firewall_tag:0:63}"
firewall_rule="tee-attest-${profile}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
firewall_rule="${firewall_rule:0:63}"

attestation_source_ranges="${GCP_ATTESTATION_ALLOWED_CIDRS:-}"
attestation_source_ranges="${attestation_source_ranges//[[:space:]]/}"
if [[ -z "${attestation_source_ranges}" ]]; then
  runner_ipv4=""
  for endpoint in \
    "https://api.ipify.org" \
    "https://ifconfig.me/ip" \
    "https://checkip.amazonaws.com"; do
    candidate="$(curl -fsS --max-time 5 "${endpoint}" 2>/dev/null | tr -d '[:space:]' || true)"
    if [[ "${candidate}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      runner_ipv4="${candidate}"
      break
    fi
  done

  if [[ -z "${runner_ipv4}" ]]; then
    echo "::error::Unable to determine runner egress IPv4. Set GCP_ATTESTATION_ALLOWED_CIDRS repository variable (comma-separated CIDRs)."
    exit 1
  fi

  attestation_source_ranges="${runner_ipv4}/32"
fi
echo "Attestation firewall source ranges: ${attestation_source_ranges}"

merod_version="${GCP_ATTESTATION_MEROD_VERSION:-${GATED_MEROD_VERSION:-}}"
if [[ -z "${merod_version}" ]]; then
  # Prefer merodVersion from versions.json (supports RC/pre-releases)
  pinned_version="$(jq -r '.merodVersion // empty' versions.json 2>/dev/null || true)"
  if [[ -n "${pinned_version}" ]]; then
    echo "Resolving merod from versions.json: ${pinned_version}"
    release_json="$(curl -fsSL \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: Bearer ${GH_TOKEN}" \
      "https://api.github.com/repos/calimero-network/core/releases/tags/${pinned_version}" 2>/dev/null || true)"
  fi
  if [[ -z "${pinned_version}" || ! "$(jq -r '.tag_name // empty' <<< "${release_json}" 2>/dev/null)" ]]; then
    echo "Resolving latest calimero-network/core release tag..."
    release_json="$(curl -fsSL \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: Bearer ${GH_TOKEN}" \
      "https://api.github.com/repos/calimero-network/core/releases/latest" 2>/dev/null || true)"
  fi
  merod_version="$(jq -r '.tag_name // empty' <<< "${release_json}" 2>/dev/null || true)"
  if [[ -z "${merod_version}" ]]; then
    echo "Could not resolve core release from API; using image_version as fallback: ${image_version}"
    merod_version="${image_version}"
  else
    for required_asset in \
      "merod_x86_64-unknown-linux-gnu.tar.gz" \
      "meroctl_x86_64-unknown-linux-gnu.tar.gz" \
      "mero-auth_x86_64-unknown-linux-gnu.tar.gz"; do
      if ! jq -e --arg asset "${required_asset}" '.assets | any(.name == $asset)' <<< "${release_json}" >/dev/null 2>&1; then
        echo "::error::Core release '${merod_version}' missing required asset: ${required_asset}"
        exit 1
      fi
    done
  fi
fi
echo "Using merod_version: ${merod_version}"

instance_name="tdx-${profile}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
instance_name="${instance_name:0:63}"
artifacts_dir="${RUNNER_TEMP}/tdx-attestation-${profile}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
mkdir -p "${artifacts_dir}"

{
  echo "profile=${profile}"
  echo "cpu_architecture=${cpu_architecture}"
  echo "image_name=${image_name}"
  echo "image_project=${image_project}"
  echo "vm_project=${vm_project}"
  echo "vm_zone=${vm_zone}"
  echo "vm_region=${vm_region}"
  echo "vm_subnetwork=${vm_subnetwork}"
  echo "vm_subnetwork_name=${vm_subnetwork_name}"
  echo "vm_network=${vm_network}"
  echo "vm_machine_type=${vm_machine_type}"
  echo "admin_api_port=${admin_api_port}"
  echo "firewall_tag=${firewall_tag}"
  echo "firewall_rule=${firewall_rule}"
  echo "attestation_source_ranges=${attestation_source_ranges}"
  echo "merod_version=${merod_version}"
  echo "instance_name=${instance_name}"
  echo "artifacts_dir=${artifacts_dir}"
} >> "${GITHUB_OUTPUT}"
echo "Params step completed successfully."
