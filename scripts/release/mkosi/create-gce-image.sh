#!/usr/bin/env bash
# Create a GCE image from build-image.sh's output.
#
# Required env:
#   ROLE, MKOSI_OUT      build-image.sh's (merotee-ROLE.tar.gz is uploaded)
#   IMAGE_NAME           the image to create
#   IMAGE_PROJECT        the project it is created in
#   UPLOAD_BUCKET        bucket for the upload (gs:// optional); the object is
#                        removed once the image exists
# Optional env:
#   IMAGE_FAMILY, IMAGE_DESCRIPTION
#   REPLACE=true         delete an existing image of that name first (for a
#                        release re-run)
set -euo pipefail

for var in ROLE MKOSI_OUT IMAGE_NAME IMAGE_PROJECT UPLOAD_BUCKET; do
  [[ -n "${!var:-}" ]] || { echo "::error::${var} is required"; exit 1; }
done
bucket="${UPLOAD_BUCKET#gs://}"
object="gs://${bucket}/${IMAGE_NAME}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}.tar.gz"

if gcloud compute images describe "${IMAGE_NAME}" --project "${IMAGE_PROJECT}" >/dev/null 2>&1; then
  if [[ "${REPLACE:-false}" != "true" ]]; then
    echo "::error::${IMAGE_NAME} already exists in ${IMAGE_PROJECT}; refusing to replace it (REPLACE=true does)"
    exit 1
  fi
  echo "Replacing ${IMAGE_NAME} in ${IMAGE_PROJECT}"
  gcloud compute images delete "${IMAGE_NAME}" --project "${IMAGE_PROJECT}" --quiet
fi

args=(--project "${IMAGE_PROJECT}" --source-uri "${object}"
      --guest-os-features "UEFI_COMPATIBLE,TDX_CAPABLE,GVNIC")
[[ -n "${IMAGE_FAMILY:-}" ]] && args+=(--family "${IMAGE_FAMILY}")
[[ -n "${IMAGE_DESCRIPTION:-}" ]] && args+=(--description "${IMAGE_DESCRIPTION}")

gcloud storage cp "${MKOSI_OUT}/merotee-${ROLE}.tar.gz" "${object}"
gcloud compute images create "${IMAGE_NAME}" "${args[@]}"
# The bucket's lifecycle rule would remove it within a day anyway.
gcloud storage rm "${object}" || true
