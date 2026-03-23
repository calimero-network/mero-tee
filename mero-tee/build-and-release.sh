#!/usr/bin/env bash

set -euo pipefail

# MeroTEE node images: x86_64 for build; Intel TDX for confidential compute at runtime.
# First arg: profile name (locked-read-only|debug-read-only|debug) = build only that profile (GCP matrix); else build all three.
case "${1:-}" in
  locked-read-only|debug-read-only|debug)
    build_only_profile="${1}"
    ;;
  *)
    build_only_profile=""
    ;;
esac
versions="$(<versions.json)"
image_version="$(echo "$versions" | jq -r '.imageVersion')"
merod_version="${GATED_MEROD_VERSION:-$(echo "$versions" | jq -r '.merodVersion // empty')}"
if [[ -z "${merod_version}" ]]; then
  echo "::error::merodVersion required: set GATED_MEROD_VERSION or merodVersion in versions.json (core tag, e.g. 0.10.0)"
  exit 1
fi
traefik_version="$(echo "$versions" | jq -r '.traefikVersion')"
node_exporter_version="$(echo "$versions" | jq -r '.nodeExporterVersion')"
vmagent_version="$(echo "$versions" | jq -r '.vmagentVersion')"
vector_version="$(echo "$versions" | jq -r '.vectorVersion')"

packer_args=(
  -var "version=${image_version}"
  -var "merod_version=${merod_version}"
  -var "traefik_version=${traefik_version}"
  -var "node_exporter_version=${node_exporter_version}"
  -var "vmagent_version=${vmagent_version}"
  -var "vector_version=${vector_version}"
  --var-file "ubuntu-x86.pkrvars.hcl"
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
