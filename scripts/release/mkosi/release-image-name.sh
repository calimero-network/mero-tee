#!/usr/bin/env bash
# The GCE name, family and description of a release image, as every release
# since the first has published them. They are a cross-repo contract:
# mdma's dispatcher finds images by these prefixes (`tee_image_name_prefix` /
# `tee_image_family_prefix`), so the mkosi images keep them, the node's frozen
# "questing-25-10" included.
#
#   release-image-name.sh ROLE PROFILE VERSION [SUFFIX]
#
# Prints name=, family= and description= lines, for $GITHUB_OUTPUT or eval. A
# SUFFIX (a non-release build, see IMAGE_SUFFIX) names the image apart and puts
# it in the "-dev" family.
set -euo pipefail
role="$1" profile="$2" version="$3" suffix="${4:-}"
case "${profile}" in
  locked-read-only | debug-read-only | debug) ;;
  *) echo "release-image-name.sh: unknown profile '${profile}'" >&2; exit 2 ;;
esac
dev=""
[[ -n "${suffix}" ]] && dev="-dev"
v="${version//./-}"
case "${role}" in
  node)
    name="merotee-ubuntu-questing-25-10-${profile}-${v}${suffix}"
    family="merotee-ubuntu-questing-${profile}${dev}"
    description="MeroTEE ${profile} profile image, built with mkosi from Ubuntu 26.04 LTS (Resolute Raccoon) packages, with Traefik and mero-auth. Name retains the questing-25-10 prefix for dispatcher compatibility." ;;
  kms)
    name="merotee-kms-${profile}-${v}${suffix}"
    family="merotee-kms-${profile}${dev}"
    description="MeroTEE mero-kms TDX cluster ${profile} image, built with mkosi from Ubuntu 26.04 LTS (Resolute Raccoon) packages." ;;
  agent)
    name="merotee-agent-${profile}-${v}${suffix}"
    family="merotee-agent-${profile}${dev}"
    description="MeroTEE private agent ${profile} image, built with mkosi from Ubuntu 26.04 LTS (Resolute Raccoon) packages, with mero-agent-gate." ;;
  inference)
    name="merotee-inference-${profile}-${v}${suffix}"
    family="merotee-inference-${profile}${dev}"
    description="MeroTEE private inference ${profile} image (GPU TDX), built with mkosi from Ubuntu 26.04 LTS (Resolute Raccoon) packages, with vLLM and mero-inference-gate." ;;
  *) echo "release-image-name.sh: unknown role '${role}'" >&2; exit 2 ;;
esac
if (( ${#name} > 63 )); then
  echo "release-image-name.sh: ${name} is longer than GCE's 63 characters" >&2
  exit 2
fi
printf 'name=%s\nfamily=%s\ndescription=%s\n' "${name}" "${family}" "${description}"
