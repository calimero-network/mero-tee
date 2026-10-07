#!/usr/bin/env bash
set -euo pipefail

# Boot an agent image on a real TDX VM, measure it, and provision it
# (docs/design/private-agents.md, phase 4).
#
# The VM runs with `ephemeral-store=true`: its state lives in TD memory and it
# needs no KMS, because no KMS can list this image until it has been measured.
# The probe then:
#
#   1. asks mero-agent-gate for a quote over a fresh nonce, has Intel Trust
#      Authority verify it, and extracts its measurements -- the agent policy
#      a KMS image is built with (`kms_agent_policy_file`) and a provisioner
#      verifies against;
#   2. runs `mero-agent-provision provision` against the gate with that policy,
#      so the quote is verified again by the same code a provisioner uses, and
#      a throwaway secret is sealed to the TD with a throwaway provisioner key;
#   3. checks the gate reports itself provisioned.
#
# Creates and always deletes its own VM and firewall rule; the image is the
# caller's to keep or delete.
#
# Required env:
#   IMAGE, IMAGE_PROJECT   the agent image to boot
#   PROFILE                its lockdown profile
#   PROBE_NAME             lowercase prefix for the VM, firewall rule and tag
#   VM_PROJECT, VM_ZONE, VM_MACHINE_TYPE
#   ITA_API_KEY
#   PROVISION_BIN          a built mero-agent-provision
#   OUT_DIR                where attest responses, ITA evidence and the policy go
# Optional env:
#   PROVISION_MODE         key (default): seal with PROVISIONER_KEY, a provisioner
#                          the image lists; unauthenticated: Base mode, for a
#                          debug image built without a list; skip: measure only
#                          (a release, which holds no provisioner's private key)
#   PROVISIONER_KEY        the provisioner secret, for PROVISION_MODE=key
#   GATE_PORT (8090), WAIT_TIMEOUT_MINUTES (15), ITA_APPRAISAL_URL,
#   AGENT_ALLOWED_TCB_STATUSES (uptodate; a declared release input, as for the
#   KMS, not a reading)
#
# Output: ${OUT_DIR}/agent-attestation-policy.${PROFILE}.json

PROVISION_MODE="${PROVISION_MODE:-key}"
case "${PROVISION_MODE}" in
  key | unauthenticated | skip) ;;
  *) echo "::error::PROVISION_MODE must be key, unauthenticated or skip"; exit 1 ;;
esac
required=(IMAGE IMAGE_PROJECT PROFILE PROBE_NAME VM_PROJECT VM_ZONE VM_MACHINE_TYPE ITA_API_KEY OUT_DIR)
[[ "${PROVISION_MODE}" == skip ]] || required+=(PROVISION_BIN)
[[ "${PROVISION_MODE}" == key ]] && required+=(PROVISIONER_KEY)
for var in "${required[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    echo "::error::${var} is required"
    exit 1
  fi
done
GATE_PORT="${GATE_PORT:-8090}"
WAIT_TIMEOUT_MINUTES="${WAIT_TIMEOUT_MINUTES:-15}"
ITA_APPRAISAL_URL="${ITA_APPRAISAL_URL:-https://api.trustauthority.intel.com/appraisal/v2/attest}"
AGENT_ALLOWED_TCB_STATUSES="${AGENT_ALLOWED_TCB_STATUSES:-uptodate}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
mkdir -p "${OUT_DIR}"

vm="${PROBE_NAME}-a"
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
  --description "mero-agent image probe ${GITHUB_RUN_ID:-local}"
firewall_created="true"

vm_created="true"
gcloud compute instances create "${vm}" \
  --project "${VM_PROJECT}" --zone "${VM_ZONE}" \
  --machine-type "${VM_MACHINE_TYPE}" \
  --confidential-compute-type TDX --maintenance-policy TERMINATE \
  --min-cpu-platform "Intel Sapphire Rapids" \
  --no-service-account --no-scopes \
  --image "${IMAGE}" --image-project "${IMAGE_PROJECT}" \
  --metadata "ephemeral-store=true" \
  --tags "${PROBE_NAME}"
ip="$(gcloud compute instances describe "${vm}" --project "${VM_PROJECT}" --zone "${VM_ZONE}" \
  --format='value(networkInterfaces[0].accessConfigs[0].natIP)')"
gate="http://${ip}:${GATE_PORT}"

deadline=$(( $(date +%s) + WAIT_TIMEOUT_MINUTES * 60 ))
until curl -fsS --max-time 5 "${gate}/health" >"${OUT_DIR}/health-before.json"; do
  if (( $(date +%s) >= deadline )); then
    echo "::error::the gate at ${gate} never answered /health"
    exit 1
  fi
  sleep 10
done
jq -e '.provisioned == false' "${OUT_DIR}/health-before.json" >/dev/null \
  || { echo "::error::a fresh gate already reports secrets: $(cat "${OUT_DIR}/health-before.json")"; exit 1; }

# --- 1. measure ---------------------------------------------------------------
nonce="$(head -c 32 /dev/urandom | base64 -w0)"
curl -fsS --max-time 30 -X POST "${gate}/attest" \
  -H 'content-type: application/json' \
  -d "{\"nonceB64\":\"${nonce}\"}" >"${OUT_DIR}/agent-attest.json"
mkdir -p "${OUT_DIR}/agent-ita"
python3 "${repo_root}/scripts/attestation/shared/verify_tdx_quote_ita.py" \
  --attest-response "${OUT_DIR}/agent-attest.json" \
  --output-dir "${OUT_DIR}/agent-ita" \
  --ita-url "${ITA_APPRAISAL_URL}" \
  --ita-api-key "${ITA_API_KEY}"
python3 "${repo_root}/scripts/attestation/shared/extract_tdx_policy_candidates.py" \
  --claims "${OUT_DIR}/agent-ita/external-attestation-token-claims.json" \
  --attest-response "${OUT_DIR}/agent-attest.json" \
  --output-json "${OUT_DIR}/agent-measurements.json" \
  --allow-missing-tcb

policy="${OUT_DIR}/agent-attestation-policy.${PROFILE}.json"
jq --arg profile "${PROFILE}" --arg tcb "${AGENT_ALLOWED_TCB_STATUSES}" '{
    schema_version: 1,
    role: "agent",
    profile: $profile,
    allowed_tcb_statuses: ($tcb | split(",") | map(select(length > 0))),
    allowed_mrtd: .policy.allowed_mrtd,
    allowed_rtmr0: .policy.allowed_rtmr0,
    allowed_rtmr1: .policy.allowed_rtmr1,
    allowed_rtmr2: .policy.allowed_rtmr2,
    allowed_rtmr3: .policy.allowed_rtmr3
  }' "${OUT_DIR}/agent-measurements.json" >"${policy}"
jq -e '[.allowed_tcb_statuses, .allowed_mrtd, .allowed_rtmr0, .allowed_rtmr1, .allowed_rtmr2, .allowed_rtmr3]
  | all(type == "array" and length > 0)' "${policy}" >/dev/null \
  || { echo "::error::the agent policy is incomplete: $(cat "${policy}")"; exit 1; }

# --- 2. provision, as a provisioner would ---------------------------------------
if [[ "${PROVISION_MODE}" != skip ]]; then
  auth=(--key "${PROVISIONER_KEY:-}")
  [[ "${PROVISION_MODE}" == unauthenticated ]] && auth=(--unauthenticated)
  printf '{"secrets":{"PROBE_SECRET":"%s"}}' "probe-${GITHUB_RUN_ID:-local}" >"${OUT_DIR}/probe-secrets.json"
  "${PROVISION_BIN}" provision --gate "${gate}" --policy "${policy}" \
    "${auth[@]}" --secrets "${OUT_DIR}/probe-secrets.json" \
    | tee "${OUT_DIR}/provision.json"
  rm -f "${OUT_DIR}/probe-secrets.json"
  jq -e '.written == ["PROBE_SECRET"]' "${OUT_DIR}/provision.json" >/dev/null \
    || { echo "::error::the gate did not write the probe secret"; exit 1; }

  # --- 3. the gate says so ------------------------------------------------------
  curl -fsS --max-time 5 "${gate}/health" >"${OUT_DIR}/health-after.json"
  jq -e '.provisioned == true' "${OUT_DIR}/health-after.json" >/dev/null \
    || { echo "::error::the gate does not report itself provisioned"; exit 1; }
fi

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "## Agent TDX image (${PROFILE}, image \`${IMAGE}\`)"
    echo "Quote verified by ITA; provisioning: ${PROVISION_MODE}."
    echo '```json'
    jq . "${policy}"
    echo '```'
  } >> "${GITHUB_STEP_SUMMARY}"
fi
echo "Agent policy: ${policy}"
