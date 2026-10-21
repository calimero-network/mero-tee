#!/usr/bin/env bash
set -euo pipefail

# Boot an inference image on a GPU TDX VM (a3, H100 in confidential-computing
# mode) with `measure-only=true`, take its quote, have Intel Trust Authority
# verify it, and write the release's inference allowlist
# (docs/design/private-inference.md, "Release").
#
# With MODEL_REPO set it serves that model instead (node-image-mkosi.yaml,
# role inference): the VM gets the model metadata, a scratch disk and a
# throwaway access token, and the probe waits for vLLM, checks /attest names
# the configuration and carries GPU evidence, and runs one chat completion.
# No allowlist is written then: RTMR3 includes the model's event.
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
#   MODEL_REPO, MODEL_REVISION, MODEL_SHA256  serve this model (see above)
#   SERVED_MODEL_NAME, ENGINE_ARGS (JSON), MODEL_DISK_GB (200)
#
# Output: ${OUT_DIR}/inference-attestation-policy.${PROFILE}.json (measure-only),
#   ${OUT_DIR}/inference-attest.json and, with a model, inference-chat.json

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
mkdir -p "${OUT_DIR}"
extra_disk=()
if [[ -n "${MODEL_REPO:-}" ]]; then
  for var in MODEL_REVISION MODEL_SHA256; do
    [[ -n "${!var:-}" ]] || { echo "::error::${var} is required with MODEL_REPO"; exit 1; }
  done
  access_token="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  token_hash="$(printf '%s' "${access_token}" | sha256sum | cut -d' ' -f1)"
  # A metadata file per key: engine-args is JSON, which --metadata's commas break.
  meta_dir="$(mktemp -d)"
  printf '%s' "${MODEL_REPO}" >"${meta_dir}/model-repo"
  printf '%s' "${MODEL_REVISION}" >"${meta_dir}/model-revision"
  printf '%s' "${MODEL_SHA256}" >"${meta_dir}/model-sha256"
  printf '%s' "${SERVED_MODEL_NAME:-}" >"${meta_dir}/served-model-name"
  printf '%s' "${ENGINE_ARGS:-{\}}" >"${meta_dir}/engine-args"
  printf '%s' "${token_hash}" >"${meta_dir}/access-token-sha256"
  vm_metadata="model-store=disk$(log_auth_metadata)"
  extra_disk=(
    --metadata-from-file "model-repo=${meta_dir}/model-repo,model-revision=${meta_dir}/model-revision,model-sha256=${meta_dir}/model-sha256,served-model-name=${meta_dir}/served-model-name,engine-args=${meta_dir}/engine-args,access-token-sha256=${meta_dir}/access-token-sha256"
    --create-disk "device-name=model,size=${MODEL_DISK_GB:-200}GB,type=pd-ssd,auto-delete=yes"
  )
else
  vm_metadata="measure-only=true$(log_auth_metadata)"
fi

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
  "${extra_disk[@]}" \
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
if [[ -z "${MODEL_REPO:-}" ]]; then
  jq -e '.measureOnly == true and .model == null' "${OUT_DIR}/inference-health.json" >/dev/null \
    || { echo "::error::the measurement VM serves a model: $(cat "${OUT_DIR}/inference-health.json")"; exit 1; }
else
  # The gate answers "starting" until vLLM has loaded the weights.
  until jq -e '.status == "ok"' "${OUT_DIR}/inference-health.json" >/dev/null 2>&1; do
    if (( $(date +%s) >= deadline )); then
      echo "::error::vLLM never became ready: $(cat "${OUT_DIR}/inference-health.json" 2>/dev/null)"
      exit 1
    fi
    sleep 20
    curl -fsSk --max-time 5 "${gate}/health" >"${OUT_DIR}/inference-health.json" || true
  done
fi

nonce="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
curl -fsSk --max-time 90 -X POST "${gate}/attest" \
  -H 'content-type: application/json' \
  -d "{\"nonceHex\":\"${nonce}\"}" >"${OUT_DIR}/inference-attest.json"
if [[ -z "${MODEL_REPO:-}" ]]; then
  jq -e '.configJson == ""' "${OUT_DIR}/inference-attest.json" >/dev/null \
    || { echo "::error::the measurement VM attests to a model configuration"; exit 1; }
else
  jq -e --arg repo "${MODEL_REPO}" --arg nonce "${nonce}" '
      (.configJson | fromjson | .repo == $repo)
      and (.gpuJson != null) and (.gpuJson | fromjson | .nonce == $nonce)' \
    "${OUT_DIR}/inference-attest.json" >/dev/null \
    || { echo "::error::/attest does not name the model or carries no GPU evidence for this nonce"; exit 1; }
  model="$(jq -r '.configJson | fromjson | .servedModelName' "${OUT_DIR}/inference-attest.json")"
  curl -fsSk --max-time 300 -X POST "${gate}/v1/chat/completions" \
    -H "authorization: Bearer ${access_token}" -H 'content-type: application/json' \
    -d "{\"model\":\"${model}\",\"max_tokens\":32,\"messages\":[{\"role\":\"user\",\"content\":\"Say hello.\"}]}" \
    >"${OUT_DIR}/inference-chat.json"
  jq -e '.choices[0].message.content | length > 0' "${OUT_DIR}/inference-chat.json" >/dev/null \
    || { echo "::error::no answer from the model: $(cat "${OUT_DIR}/inference-chat.json")"; exit 1; }
  echo "Answer: $(jq -r '.choices[0].message.content' "${OUT_DIR}/inference-chat.json")"
  if [[ "$(curl -sk -o /dev/null -w '%{http_code}' -X POST "${gate}/v1/chat/completions" -d '{}')" != 401 ]]; then
    echo "::error::the gate served a caller without a token"; exit 1
  fi
fi
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

if [[ -n "${MODEL_REPO:-}" ]]; then
  echo "Served ${MODEL_REPO}@${MODEL_REVISION}; no allowlist from a VM with a model"
  exit 0
fi

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
