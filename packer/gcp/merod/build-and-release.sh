#!/usr/bin/env bash

set -euo pipefail

# MeroTEE only supports Intel x86_64 architecture for TDX confidential computing.
# First arg: "intel" (or empty) = build all three profiles; or a profile name (locked-read-only, debug-read-only, debug) = build only that profile (GCP workflow matrix).
case "${1:-intel}" in
  locked-read-only|debug-read-only|debug)
    cpu_architecture="intel"
    build_only_profile="${1}"
    ;;
  *)
    cpu_architecture="${1:-intel}"
    build_only_profile=""
    ;;
esac
versions="$(<versions.json)"
image_version="$(echo "$versions" | jq -r '.imageVersion')"
traefik_version="$(echo "$versions" | jq -r '.traefikVersion')"
node_exporter_version="$(echo "$versions" | jq -r '.nodeExporterVersion')"
vmagent_version="$(echo "$versions" | jq -r '.vmagentVersion')"
vector_version="$(echo "$versions" | jq -r '.vectorVersion')"

packer_args=(
  -var "version=${image_version}"
  -var "traefik_version=${traefik_version}"
  -var "node_exporter_version=${node_exporter_version}"
  -var "vmagent_version=${vmagent_version}"
  -var "vector_version=${vector_version}"
  --var-file "ubuntu-${cpu_architecture}.pkrvars.hcl"
)

# Optional CI overrides. If unset, ubuntu.pkr.hcl defaults are used.
resolved_project_id="${PACKER_GCP_PROJECT_ID:-${GOOGLE_CLOUD_PROJECT:-${CLOUDSDK_CORE_PROJECT:-}}}"
if [[ -n "${resolved_project_id}" ]]; then
  packer_args+=(-var "project_id=${resolved_project_id}")
fi
if [[ -n "${PACKER_GCP_REGION:-}" ]]; then
  packer_args+=(-var "region=${PACKER_GCP_REGION}")
fi
if [[ -n "${PACKER_GCP_ZONE:-}" ]]; then
  packer_args+=(-var "zone=${PACKER_GCP_ZONE}")
fi
if [[ -n "${PACKER_GCP_SUBNETWORK:-}" ]]; then
  packer_args+=(-var "subnetwork=${PACKER_GCP_SUBNETWORK}")
fi
if [[ -n "${PACKER_GCP_SOURCE_IMAGE:-}" ]]; then
  packer_args+=(-var "source_image=${PACKER_GCP_SOURCE_IMAGE}")
fi

packer_cmd=(packer build)
if [[ "${PACKER_FORCE_BUILD:-false}" == "true" ]]; then
  echo "PACKER_FORCE_BUILD=true; enabling packer -force to replace pre-existing image artifacts"
  packer_cmd+=(-force)
fi

# Build profile(s): one (when build_only_profile set, e.g. GCP matrix) or all three (e.g. local / Packer Release).
if [[ -n "${build_only_profile:-}" ]]; then
  profiles=("${build_only_profile}")
else
  profiles=(locked-read-only debug-read-only debug)
fi
for lockdown_profile in "${profiles[@]}"; do
  echo "Building profile=${lockdown_profile} image_version=${image_version}"
  "${packer_cmd[@]}" -var "lockdown_profile=${lockdown_profile}" "${packer_args[@]}" ubuntu.pkr.hcl
done
