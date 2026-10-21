#!/usr/bin/env bash
set -euo pipefail

# Boot an inference image on a GPU TDX VM (a3, H100 in confidential-computing
# mode) with `measure-only=true`, take its quote, have Intel Trust Authority
# verify it, and write the release's inference allowlist
# (docs/design/private-inference.md, "Release").
#
# measure-only loads no model, so RTMR3 holds the image event alone: the base
# every client replays the model's configuration event onto. The VM's shape is
# the one hosts run on, because RTMR0 measures it.
#
# Creates and always deletes its own VM and firewall rule; the image is the
# caller's to keep or delete.
#
# Required env:
#   IMAGE, IMAGE_PROJECT   the inference image to boot
#   PROFILE                its lockdown profile
#   PROBE_NAME             lowercase prefix for the VM, firewall rule and tag
#   VM_PROJECT, VM_ZONE, VM_MACHINE_TYPE   an a3 shape in a zone that has it
#   ITA_API_KEY
#   OUT_DIR                where the attest response, ITA evidence and the policy go
# Optional env:
#   VM_PROVISIONING_MODEL  STANDARD (default) or SPOT: GPU capacity is scarce
#   GATE_PORT (8443), WAIT_TIMEOUT_MINUTES (20), ITA_APPRAISAL_URL,
#   INFERENCE_ALLOWED_TCB_STATUSES (uptodate; a declared release input)
#   LOGS_ENDPOINT, OBSERVABILITY_TOKEN_FILE  the log-auth check, as for the agent
#
# Output: ${OUT_DIR}/inference-attestation-policy.${PROFILE}.json

required=(IMAGE IMAGE_PROJECT PROFILE PROBE_NAME VM_PROJECT VM_ZONE VM_MACHINE_TYPE ITA_API_KEY OUT_DIR)
for var in "${required[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    echo "::error::${var} is required"
    exit 1
  fi
done
GATE_PORT="${GATE_PORT:-8443}"
WAIT_TIMEOUT_MINUTES="${WAIT_TIMEOUT_MINUTES:-20}"
ITA_APPRAISAL_URL="${ITA_APPRAISAL_URL:-https://api.trustauthority.intel.com/appraisal/v2/attest}"
INFERENCE_ALLOWED_TCB_STATUSES="${INFERENCE_ALLOWED_TCB_STATUSES:-uptodate}"
VM_PROVISIONING_MODEL="${VM_PROVISIONING_MODEL:-STANDARD}"
case "${VM_PROVISIONING_MODEL}" in
  STANDARD) provisioning=() ;;
  SPOT) provisioning=(--provisioning-model SPOT --instance-termination-action DELETE) ;;
  *) echo "::error::VM_PROVISIONING_MODEL must be STANDARD or SPOT"; exit 1 ;;
esac

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
# shellcheck source=scripts/ci/gcp_create_instance.sh
source "${repo_root}/scripts/ci/gcp_create_instance.sh"
# shellcheck source=scripts/ci/probes/log_auth_metadata.sh
source "${repo_root}/scripts/ci/probes/log_auth_metadata.sh"
vm_metadata="measure-only=true$(log_auth_metadata)"
mkdir -p "${OUT_DIR}"

vm="${PROBE_NAME}-i"
firewall="${PROBE_NAME}"
vm_created="false"
firewall_created="false"

cleanup() {
  local rc=$?
  if (( rc != 0 )) && [[ "${vm_created}" == "true" ]]; then
    echo "::group::serial output of ${vm}"
    gcloud compute instances get-serial-port-output "${vm}" \
      --project "${VM_PROJECT}" --zone "${VM_ZONE}" 2>/dev/null | tail -300 || true
    echo "::endgroup::"
  fi
  if [[ "${vm_created}" == "true" ]]; then
    gcloud compute instances delete "${vm}" \
      --project "${VM_PROJECT}" --zone "${VM_ZONE}" --delete-disks=all --quiet || true
  fi
  if [[ "${firewall_created}" == "true" ]]; then
    gcloud compute firewall-rules delete "${firewall}" --project "${VM_PROJECT}" --quiet || true
  fi
  exit "${rc}"
}
trap cleanup EXIT

runner_ip="$(curl -fsS https://api.ipify.org)"
gcloud compute firewall-rules create "${firewall}" \
  --project "${VM_PROJECT}" --network default --direction INGRESS \
  --action ALLOW --rules "tcp:${GATE_PORT}" \
  --source-ranges "${runner_ip}/32" \
  --target-tags "${PROBE_NAME}" \
  --description "mero-inference image probe ${GITHUB_RUN_ID:-local}"
firewall_created="true"

# The image is several GB larger than the other roles' (vLLM, CUDA in torch),
# so the boot disk is sized for it. No min-cpu-platform: a3 fixes it.
vm_created="true"
gcp_create_instance "${vm}" "${VM_PROJECT}" "${VM_ZONE}" \
  --machine-type "${VM_MACHINE_TYPE}" \
  --confidential-compute-type TDX --maintenance-policy TERMINATE \
  "${provisioning[@]}" \
  --boot-disk-size 100GB \
  --no-service-account --no-scopes \
  --image "${IMAGE}" --image-project "${IMAGE_PROJECT}" \
  --metadata "${vm_metadata}" \
  --tags "${PROBE_NAME}"
ip="$(gcloud compute instances describe "${vm}" --project "${VM_PROJECT}" --zone "${VM_ZONE}" \
  --format='value(networkInterfaces[0].accessConfigs[0].natIP)')"
gate="https://${ip}:${GATE_PORT}"

# The gate's certificate is self-signed, made in the TD: -k here, and the key
# it names is not what this probe checks (that is a client's job, per quote).
deadline=$(( $(date +%s) + WAIT_TIMEOUT_MINUTES * 60 ))
until curl -fsSk --max-time 5 "${gate}/health" >"${OUT_DIR}/inference-health.json"; do
  if (( $(date +%s) >= deadline )); then
    echo "::error::the gate at ${gate} never answered /health"
    exit 1
  fi
  sleep 10
done
jq -e '.measureOnly == true and .model == null' "${OUT_DIR}/inference-health.json" >/dev/null \
  || { echo "::error::the measurement VM serves a model: $(cat "${OUT_DIR}/inference-health.json")"; exit 1; }

nonce="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
curl -fsSk --max-time 90 -X POST "${gate}/attest" \
  -H 'content-type: application/json' \
  -d "{\"nonceHex\":\"${nonce}\"}" >"${OUT_DIR}/inference-attest.json"
jq -e '.configJson == ""' "${OUT_DIR}/inference-attest.json" >/dev/null \
  || { echo "::error::the measurement VM attests to a model configuration"; exit 1; }
mkdir -p "${OUT_DIR}/inference-ita"
python3 "${repo_root}/scripts/attestation/shared/verify_tdx_quote_ita.py" \
  --attest-response "${OUT_DIR}/inference-attest.json" \
  --output-dir "${OUT_DIR}/inference-ita" \
  --ita-url "${ITA_APPRAISAL_URL}" \
  --ita-api-key "${ITA_API_KEY}"
python3 "${repo_root}/scripts/attestation/shared/extract_tdx_policy_candidates.py" \
  --claims "${OUT_DIR}/inference-ita/external-attestation-token-claims.json" \
  --attest-response "${OUT_DIR}/inference-attest.json" \
  --output-json "${OUT_DIR}/inference-measurements.json" \
  --allow-missing-tcb \
  --keep-outofdate

# allowed_rtmr3 is the base: RTMR3 after the image event, before any model's.
policy="${OUT_DIR}/inference-attestation-policy.${PROFILE}.json"
jq --arg profile "${PROFILE}" --arg tcb "${INFERENCE_ALLOWED_TCB_STATUSES}" --arg shape "${VM_MACHINE_TYPE}" '{
    schema_version: 1,
    role: "inference",
    profile: $profile,
    machine_type: $shape,
    rtmr3_extends: "calimero-inference-config-v1",
    allowed_tcb_statuses: ($tcb | split(",") | map(select(length > 0))),
    allowed_mrtd: .policy.allowed_mrtd,
    allowed_rtmr0: .policy.allowed_rtmr0,
    allowed_rtmr1: .policy.allowed_rtmr1,
    allowed_rtmr2: .policy.allowed_rtmr2,
    allowed_rtmr3: .policy.allowed_rtmr3
  }' "${OUT_DIR}/inference-measurements.json" >"${policy}"
jq -e '[.allowed_tcb_statuses, .allowed_mrtd, .allowed_rtmr0, .allowed_rtmr1, .allowed_rtmr2, .allowed_rtmr3]
  | all(type == "array" and length > 0)' "${policy}" >/dev/null \
  || { echo "::error::the inference policy is incomplete: $(cat "${policy}")"; exit 1; }

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## Inference GPU TDX image (${PROFILE}, image \`${IMAGE}\`, ${VM_MACHINE_TYPE})"
    echo "Quote verified by ITA; RTMR3 is the image event alone (measure-only)."
    echo '```json'
    jq . "${policy}"
    echo '```'
  } >> "${GITHUB_STEP_SUMMARY}"
fi
echo "Inference policy: ${policy}"
