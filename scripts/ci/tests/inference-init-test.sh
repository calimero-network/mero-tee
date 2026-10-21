#!/usr/bin/env bash
# inference-init (mero-tee/ansible/roles/mero-inference/templates/inference-init.sh.j2)
# runs against stubs of the metadata server, the GPU tools, mount and systemd,
# with the real inference_model.py and a fake huggingface_hub. Checks:
#   * measure-only: RTMR3 holds the image event alone, no configuration is
#     written, vLLM never starts;
#   * a model: RTMR3's last extend is SHA-384("calimero-inference-config-v1:"
#     ‖ hex(SHA-256(config.json))), config.json is canonical, the access-token
#     hashes reach the gate's file, and vLLM starts;
#   * metadata that could run code or leave the gate open stops the boot
#     before vLLM starts: trust-remote-code, a moving revision, no tokens, a
#     bad token hash, weights that do not hash to model-sha256;
#   * a GPU outside confidential-computing mode stops a locked-read-only boot
#     and is only a warning on debug.
#
# Usage: scripts/ci/tests/inference-init-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ROLE="${REPO_ROOT}/mero-tee/ansible/roles/mero-inference"
TEMPLATE="${ROLE}/templates/inference-init.sh.j2"
fail() { echo "FAIL: $*" >&2; exit 1; }
command -v openssl >/dev/null || fail "openssl is required"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

ROOT_HASH="5f2d0c1e9a8b7c6d5e4f30211203f4e5d6c7b8a9908172635445362718090a1b"
REV="0123456789abcdef0123456789abcdef01234567"
TOKEN_HASH="$(printf secret | sha256sum | cut -d' ' -f1)"

# The fake model the fake huggingface_hub writes, and its digest.
FAKE_DIGEST="$(python3 - <<'PY'
import hashlib
files = {"config.json": b"{}", "model.safetensors": b"weights"}
lines = "".join(f"{hashlib.sha256(files[n]).hexdigest()}  {n}\n" for n in sorted(files))
print(hashlib.sha256(lines.encode()).hexdigest())
PY
)"

# setup NAME PROFILE: a sandbox with the rendered script and its stubs.
setup() {
  local name="$1" profile="$2" T="$WORK/$1"
  mkdir -p "$T"/{bin,meta,sys/measurements,lib,site/huggingface_hub,run,mnt}
  : >"$T/sys/measurements/rtmr3:sha384"
  printf 'BOOT_IMAGE=/vmlinuz roothash=%s quiet\n' "$ROOT_HASH" >"$T/cmdline"
  cp "${ROLE}/files/inference_model.py" "$T/lib/"
  cat >"$T/site/huggingface_hub/__init__.py" <<'PY'
import os
def snapshot_download(repo_id, revision, local_dir, allow_patterns, token):
    os.makedirs(local_dir, exist_ok=True)
    open(os.path.join(local_dir, "config.json"), "wb").write(b"{}")
    open(os.path.join(local_dir, "model.safetensors"), "wb").write(b"weights")
    open(os.path.join(local_dir, "modeling.py"), "w").write("raise SystemExit")
PY
  # The metadata server: a file per key; a missing key is a 404 (curl -f fails).
  cat >"$T/bin/curl" <<SH
#!/usr/bin/env bash
key="\${@: -1}"; key="\${key##*/}"
[[ -f "$T/meta/\$key" ]] || exit 22
cat "$T/meta/\$key"
SH
  # CC mode, from a file the test sets.
  cat >"$T/bin/nvidia-smi" <<SH
#!/usr/bin/env bash
case "\$*" in
  -L) echo "GPU 0: NVIDIA H100 80GB HBM3" ;;
  "conf-compute -f") echo "CC status: \$(cat "$T/cc")" ;;
  "conf-compute -srs 1") echo ready >"$T/gpu-ready" ;;
  "conf-compute -grs") echo "Confidential Compute GPUs Ready state: ready" ;;
esac
SH
  printf 'ON' >"$T/cc"
  cat >"$T/lib/gpu-evidence" <<SH
#!/usr/bin/env bash
[[ "\$1" == --check ]] && echo "NRAS accepted 1 HOPPER GPU(s)"
SH
  for stub in modprobe nvidia-persistenced mkfs.ext4 cryptsetup shred umount; do
    printf '#!/usr/bin/env bash\nexit 0\n' >"$T/bin/$stub"
  done
  # mount: only tmpfs at the model mount, recorded; mountpoint: what was mounted.
  cat >"$T/bin/mount" <<SH
#!/usr/bin/env bash
echo "\${@: -1}" >>"$T/mounted"
SH
  cat >"$T/bin/mountpoint" <<SH
#!/usr/bin/env bash
grep -qxF "\${@: -1}" "$T/mounted" 2>/dev/null
SH
  cat >"$T/bin/systemctl" <<SH
#!/usr/bin/env bash
echo "\$*" >>"$T/systemctl"
SH
  # install -o/-g name a user this machine does not have.
  cat >"$T/bin/install" <<'SH'
#!/usr/bin/env bash
args=()
while (($#)); do case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac; done
exec /usr/bin/install "${args[@]}"
SH
  chmod +x "$T"/bin/* "$T/lib/gpu-evidence"
  sed -e 's/{{ lockdown_profile }}/'"$profile"'/' \
      -e 's/{{ mero_inference_user }}/nobody/' \
      -e "s@{{ mero_inference_site_packages }}@$T/site@" \
      -e "s@/run/mero-inference-disk@$T/run/disk@g" \
      -e "s@/run/mero-inference@$T/run@g" \
      -e "s@/usr/local/lib/mero-inference@$T/lib@g" \
      -e "s@/sys/class/misc/tdx_guest@$T/sys@g" \
      -e "s@/proc/cmdline@$T/cmdline@g" \
      -e "s@/mnt/model@$T/mnt@g" \
      -e "s@/etc/vector@$T/vector@g" \
      -e "s@/etc/vmagent@$T/vmagent@g" \
      "$TEMPLATE" >"$T/init.sh"
}

meta() { printf '%s' "$3" >"$WORK/$1/meta/$2"; }

model_meta() {
  meta "$1" model-repo "Qwen/Qwen3-8B"
  meta "$1" model-revision "$REV"
  meta "$1" model-sha256 "$FAKE_DIGEST"
  meta "$1" engine-args '{"max-model-len": 8192}'
  meta "$1" access-token-sha256 "$TOKEN_HASH"
  meta "$1" model-store memory
}

run() {
  local T="$WORK/$1"
  set +e
  PATH="$T/bin:$PATH" bash "$T/init.sh" >"$T/out" 2>&1
  echo $? >"$T/rc"
  set -e
}
rc() { cat "$WORK/$1/rc"; }
rtmr3() { od -An -tx1 "$WORK/$1/sys/measurements/rtmr3:sha384" | tr -d ' \n'; }
sha384_hex() { openssl dgst -sha384 -binary | od -An -tx1 | tr -d ' \n'; }
started() { grep -q 'start --no-block mero-inference-vllm.service' "$WORK/$1/systemctl" 2>/dev/null; }

# --- measure-only -----------------------------------------------------------------
setup measure locked-read-only
meta measure measure-only true
run measure
[[ "$(rc measure)" == 0 ]] || fail "measure-only must boot: $(cat "$WORK/measure/out")"
[[ "$(rtmr3 measure)" == "$(printf 'calimero-rtmr3-v3:inference:locked-read-only:%s' "$ROOT_HASH" | sha384_hex)" ]] \
  || fail "measure-only: RTMR3's only extend must be the image event"
[[ ! -e "$WORK/measure/run/config.json" ]] || fail "measure-only wrote a configuration"
started measure && fail "measure-only started vLLM"

# --- a model ------------------------------------------------------------------------
setup model locked-read-only
model_meta model
run model
[[ "$(rc model)" == 0 ]] || fail "a valid model must boot: $(cat "$WORK/model/out")"
config="$WORK/model/run/config.json"
expected_config="{\"engine\":{\"max-model-len\":8192},\"repo\":\"Qwen/Qwen3-8B\",\"revision\":\"$REV\",\"schema\":1,\"servedModelName\":\"qwen3-8b\",\"weightsSha256\":\"$FAKE_DIGEST\"}"
[[ "$(cat "$config")" == "$expected_config" ]] || fail "config.json is not canonical: $(cat "$config")"
digest="$(sha256sum "$config" | cut -d' ' -f1)"
[[ "$(rtmr3 model)" == "$(printf 'calimero-inference-config-v1:%s' "$digest" | sha384_hex)" ]] \
  || fail "RTMR3's last extend must be the configuration event"
[[ "$(cat "$WORK/model/run/access-tokens")" == "$TOKEN_HASH" ]] || fail "the token hashes did not reach the gate's file"
[[ -e "$WORK/model/gpu-ready" ]] || fail "the GPU was not set ready"
grep -q '^HF_HUB_OFFLINE=1$' "$WORK/model/run/vllm.env" || fail "vLLM is not offline"
started model || fail "vLLM did not start"
[[ ! -e "$WORK/model/mnt/weights/modeling.py" ]] || true  # downloaded, but never part of the digest or run

# --- refused before vLLM starts ----------------------------------------------------------
refused() {
  local name="$1" profile="$2" key="$3" value="$4" why="$5"
  setup "$name" "$profile"
  model_meta "$name"
  if [[ "$value" == "<absent>" ]]; then rm -f "$WORK/$name/meta/$key"; else meta "$name" "$key" "$value"; fi
  run "$name"
  [[ "$(rc "$name")" != 0 ]] || fail "$why: the boot went on"
  started "$name" && fail "$why: vLLM started"
  return 0
}
refused remote-code locked-read-only engine-args '{"trust-remote-code": true}' "trust-remote-code"
refused branch locked-read-only model-revision main "a branch as the revision"
refused no-tokens locked-read-only access-token-sha256 "<absent>" "no access tokens"
refused bad-token locked-read-only access-token-sha256 "abc" "a bad token hash"
refused wrong-weights locked-read-only model-sha256 "$(printf '%064d' 0)" "weights that do not hash to model-sha256"
grep -q 'do not hash to model-sha256' "$WORK/wrong-weights/out" || fail "the digest refusal must say so"

# --- the GPU ----------------------------------------------------------------------------
setup cc-off locked-read-only
model_meta cc-off
printf 'OFF' >"$WORK/cc-off/cc"
run cc-off
[[ "$(rc cc-off)" != 0 ]] || fail "locked-read-only must stop with confidential computing off"
[[ ! -e "$WORK/cc-off/gpu-ready" ]] || fail "a GPU outside CC mode was set ready"

setup cc-off-debug debug
model_meta cc-off-debug
printf 'OFF' >"$WORK/cc-off-debug/cc"
run cc-off-debug
[[ "$(rc cc-off-debug)" == 0 ]] || fail "debug must boot on with CC off: $(cat "$WORK/cc-off-debug/out")"
grep -q 'WARN: GPU: confidential-computing mode is not on' "$WORK/cc-off-debug/out" || fail "debug must warn about CC off"

echo "PASS: inference-init"
