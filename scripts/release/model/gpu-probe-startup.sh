#!/usr/bin/env bash
# Startup script for the GPU model probe VM (run-gpu-model-probe.sh).
#
# Installs the NVIDIA driver and vLLM, downloads the model files the runner
# pinned and checks each against its sha256, serves the model on loopback,
# runs load_probe.py against it and prints the report to the serial console
# between GPU-PROBE RESULT-BEGIN / RESULT-END, base64-encoded. Every stage
# prints `GPU-PROBE STAGE <name>`; a failure prints `GPU-PROBE FAILED <why>`
# with the tail of the log that failed. The VM serves nothing to the network.
set -Eeuo pipefail

LOG=/var/log/gpu-probe
mkdir -p "${LOG}"

say() { echo "GPU-PROBE $*" >/dev/ttyS0 || true; echo "GPU-PROBE $*"; }
tail_to_serial() {
  if [[ -f "$1" ]]; then
    tail -n "${2:-60}" "$1" | sed 's/^/GPU-PROBE LOG /' >/dev/ttyS0 || true
  fi
}
fail() { say "FAILED $*"; exit 1; }
trap 'fail "line ${LINENO}: ${BASH_COMMAND}"' ERR

md() {
  curl -fsS -H 'Metadata-Flavor: Google' \
    "http://metadata.google.internal/computeMetadata/v1/instance/attributes/$1"
}

# One run per boot: the startup script runs again if the VM reboots.
[[ -e /run/gpu-probe.started ]] && exit 0
touch /run/gpu-probe.started

DRIVER="$(md probe-driver)"
VLLM_VERSION="$(md probe-vllm-version || true)"
MAX_MODEL_LEN="$(md probe-max-model-len)"
# gcloud --metadata splits on commas, so the runner passes levels with ";".
LEVELS="$(md probe-levels)"
LEVELS="${LEVELS//;/,}"
md probe-files >/root/model-files.json
md probe-load >/root/load_probe.py

say "STAGE driver ${DRIVER}"
export DEBIAN_FRONTEND=noninteractive
{
  apt-get update
  apt-get install -y --no-install-recommends ubuntu-drivers-common python3-venv jq
  if ! ubuntu-drivers install --gpgpu "nvidia:${DRIVER}-server-open"; then
    apt-get install -y "linux-modules-nvidia-${DRIVER}-server-open-$(uname -r)" \
      "nvidia-utils-${DRIVER}-server" "nvidia-compute-utils-${DRIVER}-server"
  fi
  modprobe nvidia
  nvidia-smi
} >"${LOG}/driver.log" 2>&1 || { tail_to_serial "${LOG}/driver.log"; fail "driver install"; }

# Confidential computing: record the GPU's CC state and mark it ready, which a
# GPU in CC mode needs before CUDA work is accepted.
cc_features="$(nvidia-smi conf-compute -f 2>&1 | tr '\n' ' ' || true)"
nvidia-smi conf-compute -srs 1 >/dev/null 2>&1 || true
cc_ready="$(nvidia-smi conf-compute -grs 2>&1 | tr '\n' ' ' || true)"
gpu="$(nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader)"
say "STAGE gpu ${gpu} | ${cc_features} | ${cc_ready}"

say "STAGE vllm ${VLLM_VERSION:-latest}"
{
  python3 -m venv /opt/probe
  /opt/probe/bin/pip install --upgrade pip
  /opt/probe/bin/pip install "vllm${VLLM_VERSION:+==${VLLM_VERSION}}" "huggingface_hub[hf_transfer]"
} >"${LOG}/pip.log" 2>&1 || { tail_to_serial "${LOG}/pip.log"; fail "vllm install"; }
vllm_installed="$(/opt/probe/bin/python -c 'import vllm; print(vllm.__version__)')"

repo="$(jq -r .repo /root/model-files.json)"
rev="$(jq -r .revision /root/model-files.json)"
say "STAGE download ${repo}@${rev}"
MODEL=/models/probe
mkdir -p "${MODEL}"
t0=$(date +%s)
HF_HUB_ENABLE_HF_TRANSFER=1 /opt/probe/bin/hf download "${repo}" --revision "${rev}" \
  --local-dir "${MODEL}" >"${LOG}/download.log" 2>&1 \
  || { tail_to_serial "${LOG}/download.log"; fail "download"; }
download_s=$(( $(date +%s) - t0 ))

say "STAGE verify"
jq -r '.files[] | "\(.sha256)  \(.path)"' /root/model-files.json >/root/model-files.sha256
(cd "${MODEL}" && sha256sum --quiet -c /root/model-files.sha256) >"${LOG}/verify.log" 2>&1 \
  || { tail_to_serial "${LOG}/verify.log"; fail "a model file does not match its pinned sha256"; }

say "STAGE serve max-model-len ${MAX_MODEL_LEN}"
t0=$(date +%s)
/opt/probe/bin/vllm serve "${MODEL}" --served-model-name probe \
  --host 127.0.0.1 --port 8000 \
  --max-model-len "${MAX_MODEL_LEN}" --gpu-memory-utilization 0.92 \
  --enable-prefix-caching >"${LOG}/vllm.log" 2>&1 &
vllm_pid=$!
until curl -fsS --max-time 5 http://127.0.0.1:8000/health >/dev/null 2>&1; do
  kill -0 "${vllm_pid}" 2>/dev/null || { tail_to_serial "${LOG}/vllm.log" 80; fail "vllm exited"; }
  (( $(date +%s) - t0 < 3600 )) || { tail_to_serial "${LOG}/vllm.log" 80; fail "vllm never became healthy"; }
  sleep 10
done
load_s=$(( $(date +%s) - t0 ))
kv_lines="$(grep -iE 'KV cache|maximum concurrency' "${LOG}/vllm.log" | tail -n 4 | tr '\n' ' ' || true)"
gpu_mem="$(nvidia-smi --query-gpu=memory.used,memory.total --format=csv,noheader)"
say "STAGE loaded in ${load_s}s | ${gpu_mem} | ${kv_lines}"

say "STAGE load ${LEVELS}"
/opt/probe/bin/python /root/load_probe.py --tokenizer "${MODEL}" --levels "${LEVELS}" \
  >/root/load.json 2>"${LOG}/load.log" \
  || { tail_to_serial "${LOG}/load.log"; tail_to_serial "${LOG}/vllm.log" 40; fail "load probe"; }

jq -n \
  --slurpfile load /root/load.json \
  --arg repo "${repo}" --arg rev "${rev}" --arg gpu "${gpu}" \
  --arg cc_features "${cc_features}" --arg cc_ready "${cc_ready}" \
  --arg vllm "${vllm_installed}" --arg driver "${DRIVER}" \
  --arg kv "${kv_lines}" --arg gpu_mem "${gpu_mem}" \
  --argjson max_model_len "${MAX_MODEL_LEN}" \
  --argjson download_s "${download_s}" --argjson load_s "${load_s}" \
  '{model: {repo: $repo, revision: $rev}, gpu: $gpu, driver: $driver, vllm: $vllm,
    confidential_compute: {features: $cc_features, ready_state: $cc_ready},
    max_model_len: $max_model_len, gpu_memory_after_load: $gpu_mem, kv_cache: $kv,
    download_s: $download_s, load_s: $load_s, load: $load[0]}' >/root/report.json

say "RESULT-BEGIN"
base64 -w 76 /root/report.json | sed 's/^/GPU-PROBE B64 /' >/dev/ttyS0
say "RESULT-END"
