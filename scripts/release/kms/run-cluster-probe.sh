#!/usr/bin/env bash
set -euo pipefail

# Boot a two-replica mero-kms cluster from a built KMS image on real TDX VMs and
# prove it works (docs/design/gcp-tdx-kms.md): the first replica generates the
# root, the second joins it through the attested join protocol, and both must
# then report the same transport key -- which derives from the root, so equal
# keys mean one root. Each replica's quote is verified by Intel Trust Authority
# and its measurements are extracted; the two must measure identically.
#
# Shared by kms-tdx-image-probe.yaml (dispatch-only, throwaway image) and
# release-kms.yaml (the release image, whose measurements become the KMS
# allowlist merod enforces). Creates and always deletes its own VMs and
# firewall rule; the image is the caller's to keep or delete.
#
# Required env:
#   IMAGE, IMAGE_PROJECT   the KMS image to boot
#   PROFILE                its lockdown profile (debug also checks dm-verity boot)
#   PROBE_NAME             lowercase prefix for the VMs, firewall rule and tag
#   VM_PROJECT, VM_ZONE, VM_MACHINE_TYPE
#   ITA_API_KEY
#   OUT_DIR                where attest responses, ITA evidence and measurements go
# Optional env:
#   KMS_PORT (8080), WAIT_TIMEOUT_MINUTES (15), ITA_APPRAISAL_URL
#
# Output: ${OUT_DIR}/kms-measurements.json, the ITA-verified policy candidates
# (`.policy.allowed_mrtd`, `allowed_rtmr0..3`, `allowed_tcb_statuses`) both
# replicas share.

for var in IMAGE IMAGE_PROJECT PROFILE PROBE_NAME VM_PROJECT VM_ZONE VM_MACHINE_TYPE ITA_API_KEY OUT_DIR; do
  if [[ -z "${!var:-}" ]]; then
    echo "::error::${var} is required"
    exit 1
  fi
done
KMS_PORT="${KMS_PORT:-8080}"
WAIT_TIMEOUT_MINUTES="${WAIT_TIMEOUT_MINUTES:-15}"
ITA_APPRAISAL_URL="${ITA_APPRAISAL_URL:-https://api.trustauthority.intel.com/appraisal/v2/attest}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
mkdir -p "${OUT_DIR}"

tag="${PROBE_NAME}"
firewall="${PROBE_NAME}"
first="${PROBE_NAME}-a"
second="${PROBE_NAME}-b"
created_vms=()
firewall_created="false"

cleanup() {
  local rc=$?
  if (( rc != 0 )); then
    for vm in "${created_vms[@]}"; do
      echo "::group::serial output of ${vm}"
      gcloud compute instances get-serial-port-output "${vm}" \
        --project "${VM_PROJECT}" --zone "${VM_ZONE}" 2>/dev/null | tail -300 || true
      echo "::endgroup::"
    done
  fi
  for vm in "${created_vms[@]}"; do
    gcloud compute instances delete "${vm}" \
      --project "${VM_PROJECT}" --zone "${VM_ZONE}" --delete-disks=all --quiet || true
  done
  if [[ "${firewall_created}" == "true" ]]; then
    gcloud compute firewall-rules delete "${firewall}" --project "${VM_PROJECT}" --quiet || true
  fi
  exit "${rc}"
}
trap cleanup EXIT

# The runner reaches /health and /attest; the replicas reach each other over
# the VPC for the join.
runner_ip="$(curl -fsS https://api.ipify.org)"
gcloud compute firewall-rules create "${firewall}" \
  --project "${VM_PROJECT}" --network default --direction INGRESS \
  --action ALLOW --rules "tcp:${KMS_PORT}" \
  --source-ranges "${runner_ip}/32,10.0.0.0/8" \
  --target-tags "${tag}" \
  --description "mero-kms cluster probe ${GITHUB_RUN_ID:-local}"
firewall_created="true"

start_replica() {
  local name="$1"
  local metadata="$2"
  created_vms+=("${name}")
  gcloud compute instances create "${name}" \
    --project "${VM_PROJECT}" --zone "${VM_ZONE}" \
    --machine-type "${VM_MACHINE_TYPE}" \
    --confidential-compute-type TDX --maintenance-policy TERMINATE \
    --min-cpu-platform "Intel Sapphire Rapids" \
    --no-service-account --no-scopes \
    --image "${IMAGE}" --image-project "${IMAGE_PROJECT}" \
    --metadata "${metadata}" \
    --tags "${tag}"
}

vm_ip() {
  gcloud compute instances describe "$1" --project "${VM_PROJECT}" --zone "${VM_ZONE}" \
    --format="value(networkInterfaces[0].$2)"
}

wait_for_root() {
  local label="$1"
  local ip="$2"
  local deadline=$(( $(date +%s) + WAIT_TIMEOUT_MINUTES * 60 ))
  until curl -fsS --max-time 5 "http://${ip}:${KMS_PORT}/health" | tee "${OUT_DIR}/${label}-health.json" \
    | jq -e '.clusterRootReady == true' >/dev/null; do
    if (( $(date +%s) >= deadline )); then
      echo "::error::${label} replica never held the root"
      cat "${OUT_DIR}/${label}-health.json" 2>/dev/null || true
      exit 1
    fi
    sleep 10
  done
  echo "${label} replica holds the root: $(cat "${OUT_DIR}/${label}-health.json")"
}

start_replica "${first}" "kms-bootstrap=true"
first_ip="$(vm_ip "${first}" 'accessConfigs[0].natIP')"
first_internal="$(vm_ip "${first}" 'networkIP')"
wait_for_root bootstrap "${first_ip}"

# A replica answering proves it booted, not WHICH root: require the verity root
# hash on the kernel cmdline and the initrd's verity setup in the boot log. Only
# the debug profile keeps a serial console.
if [[ "${PROFILE}" == "debug" ]]; then
  serial="$(gcloud compute instances get-serial-port-output "${first}" \
    --project "${VM_PROJECT}" --zone "${VM_ZONE}" 2>/dev/null || true)"
  grep -E 'Command line:.* roothash=[0-9a-f]{64} ' <<< "${serial}" \
    || { echo "::error::the booted kernel cmdline carries no dm-verity root hash"; exit 1; }
  grep -E 'veritysetup@root' <<< "${serial}" \
    || { echo "::error::the initrd never set up the dm-verity root"; exit 1; }
  grep -E 'mero-kms-init' <<< "${serial}" | tail -5 || true
fi

start_replica "${second}" "kms-peers=http://${first_internal}:${KMS_PORT}"
second_ip="$(vm_ip "${second}" 'accessConfigs[0].natIP')"
wait_for_root joiner "${second_ip}"

for label in bootstrap joiner; do
  case "${label}" in
    bootstrap) ip="${first_ip}" ;;
    joiner) ip="${second_ip}" ;;
  esac
  nonce="$(head -c 32 /dev/urandom | base64 -w0)"
  curl -fsS --max-time 30 -X POST "http://${ip}:${KMS_PORT}/attest" \
    -H 'content-type: application/json' \
    -d "{\"nonceB64\":\"${nonce}\",\"transportKey\":true}" > "${OUT_DIR}/${label}-attest.json"
  mkdir -p "${OUT_DIR}/${label}-ita"
  python3 "${repo_root}/scripts/attestation/shared/verify_tdx_quote_ita.py" \
    --attest-response "${OUT_DIR}/${label}-attest.json" \
    --output-dir "${OUT_DIR}/${label}-ita" \
    --ita-url "${ITA_APPRAISAL_URL}" \
    --ita-api-key "${ITA_API_KEY}"
  python3 "${repo_root}/scripts/attestation/shared/extract_tdx_policy_candidates.py" \
    --claims "${OUT_DIR}/${label}-ita/external-attestation-token-claims.json" \
    --attest-response "${OUT_DIR}/${label}-attest.json" \
    --output-json "${OUT_DIR}/${label}-measurements.json" \
    --allow-missing-tcb
done

# The transport key derives from the root, so two replicas report the same one
# only if they hold the same root.
first_key="$(jq -r '.transportPublicKeyB64' "${OUT_DIR}/bootstrap-attest.json")"
second_key="$(jq -r '.transportPublicKeyB64' "${OUT_DIR}/joiner-attest.json")"
echo "bootstrap replica transport key: ${first_key}"
echo "joining replica transport key:   ${second_key}"
[[ -n "${first_key}" && "${first_key}" != "null" ]] || { echo "::error::no transport key reported"; exit 1; }
[[ "${first_key}" == "${second_key}" ]] || { echo "::error::the replicas hold different roots"; exit 1; }
if ! diff <(jq -S '.policy' "${OUT_DIR}/bootstrap-measurements.json") <(jq -S '.policy' "${OUT_DIR}/joiner-measurements.json"); then
  echo "::error::the two replicas measure differently"
  exit 1
fi
cp "${OUT_DIR}/bootstrap-measurements.json" "${OUT_DIR}/kms-measurements.json"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## KMS TDX cluster (${PROFILE}, image \`${IMAGE}\`)"
    echo "Both replicas hold one root (transport key \`${first_key}\`)."
    echo '```json'
    jq '.policy' "${OUT_DIR}/kms-measurements.json"
    echo '```'
  } >> "${GITHUB_STEP_SUMMARY}"
fi
