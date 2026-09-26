#!/usr/bin/env bash
# Measure a built mero-kms TDX image: boot it as a bootstrap replica, wait until
# it holds a root, take a quote over /attest, have Intel Trust Authority verify
# it, and extract the five registers the release publishes for merod to pin.
#
# One replica is enough to measure an image: every replica of it measures the
# same, which is what the join rule relies on and what the KMS TDX image probe
# (kms-tdx-image-probe.yaml) checks with two. The VM and its firewall rule are
# deleted on exit, whatever happened.
#
# Env:
#   PROFILE, IMAGE, IMAGE_PROJECT, VM_PROJECT, VM_ZONE, VM_MACHINE_TYPE
#   RESOURCE_NAME    name for the VM, its network tag and firewall rule
#   KMS_PORT         the port mero-kms listens on (8080)
#   ITA_API_KEY      Intel Trust Authority key; ITA_APPRAISAL_URL optional
#   OUT_DIR          where attest.json, ita/ and measurements.json are written
#   WAIT_TIMEOUT_MINUTES  how long to wait for the root (default 15)
set -euo pipefail

for name in PROFILE IMAGE IMAGE_PROJECT VM_PROJECT VM_ZONE VM_MACHINE_TYPE RESOURCE_NAME KMS_PORT ITA_API_KEY OUT_DIR; do
  [[ -n "${!name:-}" ]] || { echo "::error::${name} is not set"; exit 1; }
done
WAIT_TIMEOUT_MINUTES="${WAIT_TIMEOUT_MINUTES:-15}"
mkdir -p "${OUT_DIR}"

vm="${RESOURCE_NAME}"
tag="${RESOURCE_NAME}"
firewall="${RESOURCE_NAME}"

cleanup() {
  gcloud compute instances delete "${vm}" --project "${VM_PROJECT}" --zone "${VM_ZONE}" \
    --delete-disks=all --quiet >/dev/null 2>&1 || true
  gcloud compute firewall-rules delete "${firewall}" --project "${VM_PROJECT}" \
    --quiet >/dev/null 2>&1 || true
}
trap cleanup EXIT

runner_ip="$(curl -fsS https://api.ipify.org)"
gcloud compute firewall-rules create "${firewall}" \
  --project "${VM_PROJECT}" --network default --direction INGRESS \
  --action ALLOW --rules "tcp:${KMS_PORT}" \
  --source-ranges "${runner_ip}/32" --target-tags "${tag}" \
  --description "Measure KMS image ${IMAGE} (run ${GITHUB_RUN_ID:-local})"

gcloud compute instances create "${vm}" \
  --project "${VM_PROJECT}" --zone "${VM_ZONE}" \
  --machine-type "${VM_MACHINE_TYPE}" \
  --confidential-compute-type TDX --maintenance-policy TERMINATE \
  --min-cpu-platform "Intel Sapphire Rapids" \
  --no-service-account --no-scopes \
  --image "${IMAGE}" --image-project "${IMAGE_PROJECT}" \
  --metadata "kms-bootstrap=true" \
  --tags "${tag}"

ip="$(gcloud compute instances describe "${vm}" --project "${VM_PROJECT}" --zone "${VM_ZONE}" \
  --format='value(networkInterfaces[0].accessConfigs[0].natIP)')"
deadline=$(( $(date +%s) + WAIT_TIMEOUT_MINUTES * 60 ))
until curl -fsS --max-time 5 "http://${ip}:${KMS_PORT}/health" \
    | tee "${OUT_DIR}/health.json" | jq -e '.clusterRootReady == true' >/dev/null; do
  if (( $(date +%s) >= deadline )); then
    echo "::error::the KMS replica never held a root"
    gcloud compute instances get-serial-port-output "${vm}" --project "${VM_PROJECT}" \
      --zone "${VM_ZONE}" 2>/dev/null | tail -200 || true
    exit 1
  fi
  sleep 10
done

# A replica answering proves it booted, not WHICH root it booted. The profiles
# that keep a serial console show the kernel cmdline and the initrd's verity
# setup; locked-read-only has none and runs the same seal.
if [[ "${PROFILE}" != "locked-read-only" ]]; then
  serial="$(gcloud compute instances get-serial-port-output "${vm}" --project "${VM_PROJECT}" \
    --zone "${VM_ZONE}" 2>/dev/null || true)"
  grep -qE 'Command line:.* roothash=[0-9a-f]{64} ' <<< "${serial}" \
    || { echo "::error::the booted kernel cmdline carries no dm-verity root hash"; exit 1; }
  grep -qE 'veritysetup@root' <<< "${serial}" \
    || { echo "::error::the initrd never set up the dm-verity root"; exit 1; }
fi

nonce="$(head -c 32 /dev/urandom | base64 -w0)"
curl -fsS --max-time 30 -X POST "http://${ip}:${KMS_PORT}/attest" \
  -H 'content-type: application/json' \
  -d "{\"nonceB64\":\"${nonce}\"}" > "${OUT_DIR}/attest.json"

python3 scripts/attestation/shared/verify_tdx_quote_ita.py \
  --attest-response "${OUT_DIR}/attest.json" \
  --output-dir "${OUT_DIR}/ita" \
  --ita-url "${ITA_APPRAISAL_URL:-https://api.trustauthority.intel.com/appraisal/v2/attest}" \
  --ita-api-key "${ITA_API_KEY}"

# `outofdate` is accepted as well as `uptodate`: when Intel publishes a new TCB
# level, quotes read OutOfDate until Google patches the hosts, and a strict rule
# would refuse every replica restarted in that window (docs/design/gcp-tdx-kms.md).
python3 scripts/attestation/shared/extract_tdx_policy_candidates.py \
  --claims "${OUT_DIR}/ita/external-attestation-token-claims.json" \
  --attest-response "${OUT_DIR}/attest.json" \
  --output-json "${OUT_DIR}/measurements.json" \
  --allowed-tcb-status uptodate --allowed-tcb-status outofdate \
  --allow-missing-tcb

jq '.policy' "${OUT_DIR}/measurements.json"
