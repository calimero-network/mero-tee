#!/usr/bin/env bash
# The staging probe's log-auth check must tell a node that pushed with its
# credential apart from one that pushed without it.
#
# The check itself runs only on real GCP (node-image-gcp-staging-probe.yaml,
# `log_auth_check`). Two pieces of it can be wrong without any cloud, and a
# wrong one would make that run lie:
#
#   * log_auth_receiver.py must classify each push as OK only when the bearer
#     token hashes to the expected SHA-256. A receiver that passed any token,
#     or no token at all, would turn an unauthenticated node into a green check.
#   * `node_log_auth_probe.sh verify` must pass on an authenticated push,
#     and on anything else fail with the code that names what went wrong.
#
# Here the receiver runs on localhost and gets real HTTP requests, and verify
# reads its output through a stub `gcloud` that plays the serial console.
#
# Usage: scripts/ci/tests/node-log-auth-probe-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RECEIVER="${REPO_ROOT}/scripts/ci/probes/log_auth_receiver.py"
PROBE="${REPO_ROOT}/scripts/ci/probes/node_log_auth_probe.sh"

SB="$(mktemp -d)"
RECEIVER_PID=""
cleanup() {
  [[ -z "${RECEIVER_PID}" ]] || kill "${RECEIVER_PID}" 2>/dev/null || true
  rm -rf "${SB}"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

TOKEN="expected-token-value"
WANT="$(printf '%s' "${TOKEN}" | sha256sum | awk '{print $1}')"
PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
OUT="${SB}/serial.log"

WANT_SHA256="${WANT}" PROBE_PORT="${PORT}" PROBE_OUT="${OUT}" python3 "${RECEIVER}" &
RECEIVER_PID=$!
for _ in $(seq 1 50); do
  grep -q PROBE_RECEIVER_READY "${OUT}" 2>/dev/null && break
  sleep 0.1
done
grep -q PROBE_RECEIVER_READY "${OUT}" || fail "receiver did not start"

push() {
  curl -sS -o /dev/null -w '%{http_code}' -X POST --data-binary '{"index":{}}' \
    "$@" "http://127.0.0.1:${PORT}/_bulk"
}

last_verdict() { grep -oE 'PROBE_AUTH_[A-Z]+' "${OUT}" | tail -1; }

check_push() {
  local want="$1"; shift
  local code
  code="$(push "$@")"
  [[ "${code}" == "200" ]] || fail "receiver answered ${code}; vector would back off"
  [[ "$(last_verdict)" == "${want}" ]] || fail "push $* classified $(last_verdict), want ${want}"
  echo "ok   ${want}: ${*:-no Authorization header}"
}

check_push PROBE_AUTH_NONE
check_push PROBE_AUTH_MISMATCH -H "Authorization: Bearer not-the-token"
check_push PROBE_AUTH_MISMATCH -H "Authorization: Basic ${TOKEN}"
check_push PROBE_AUTH_MISMATCH -H "Authorization: Bearer ${TOKEN}x"
check_push PROBE_AUTH_OK -H "Authorization: Bearer ${TOKEN}"

# A version probe is answered and not counted as a push.
before="$(grep -c PROBE_AUTH_ "${OUT}")"
curl -sSf -o /dev/null "http://127.0.0.1:${PORT}/"
[[ "$(grep -c PROBE_AUTH_ "${OUT}")" == "${before}" ]] || fail "a GET was counted as a push"
echo "ok   GET answered, not counted"

# --- verify, against a stub gcloud that prints a canned serial console --------
mkdir -p "${SB}/bin" "${SB}/art"
cat > "${SB}/bin/gcloud" <<STUB
#!/usr/bin/env bash
echo "\$*" >> "${SB}/gcloud-calls"
cat "${SB}/canned"
STUB
chmod +x "${SB}/bin/gcloud"

run_verify() {
  printf '%b' "$1" > "${SB}/canned"
  (cd "${REPO_ROOT}" && PATH="${SB}/bin:${PATH}" ARTIFACTS_DIR="${SB}/art" \
    VM_PROJECT=p VM_ZONE=z RUN_SUFFIX=1-1 VERIFY_TIMEOUT_SECONDS=0 \
    bash "${PROBE}" verify) > "${SB}/verify.out" 2>&1
}

expect_verify() {
  local name="$1" serial="$2" want="$3"
  if run_verify "${serial}"; then
    [[ "${want}" == "pass" ]] || fail "verify passed on ${name}: $(cat "${SB}/verify.out")"
    jq -e '.passed == true' "${SB}/art/node-log-auth-result.json" >/dev/null \
      || fail "verify passed on ${name} but the result file says otherwise"
  else
    [[ "${want}" != "pass" ]] || fail "verify failed on ${name}: $(cat "${SB}/verify.out")"
    grep -q "${want}" "${SB}/verify.out" || fail "verify on ${name} did not report ${want}: $(cat "${SB}/verify.out")"
  fi
  echo "ok   verify ${name}: ${want}"
}

expect_verify "an authenticated push" \
  'boot\nPROBE_RECEIVER_READY port=9200\nPROBE_AUTH_NONE POST /_bulk\nPROBE_AUTH_OK POST /_bulk\n' pass
expect_verify "unauthenticated pushes only" \
  'PROBE_RECEIVER_READY port=9200\nPROBE_AUTH_NONE POST /_bulk\n' LOG_PUSH_UNAUTHENTICATED
expect_verify "a wrong token" \
  'PROBE_RECEIVER_READY port=9200\nPROBE_AUTH_MISMATCH POST /_bulk\n' LOG_PUSH_WRONG_TOKEN
expect_verify "a receiver that never started" \
  'boot\n' RECEIVER_NOT_READY
expect_verify "no pushes at all" \
  'PROBE_RECEIVER_READY port=9200\n' NO_LOG_PUSHES

# --- receiver names: the release's cleanup sweep finds them by prefix ---------
# The release runs the check with RECEIVER_PREFIX=tee-attest-rcv and a
# per-profile RUN_SUFFIX; sweep-attestation-resources.sh deletes what matches.
probe_with() {
  : > "${SB}/gcloud-calls"
  printf 'PROBE_RECEIVER_READY port=9200\nPROBE_AUTH_OK POST /_bulk\n' > "${SB}/canned"
  (cd "${REPO_ROOT}" && PATH="${SB}/bin:${PATH}" ARTIFACTS_DIR="${SB}/art" \
    VM_PROJECT=p VM_ZONE=z VERIFY_TIMEOUT_SECONDS=0 "$@") > "${SB}/verify.out" 2>&1
}

probe_with env RUN_SUFFIX=1-1 bash "${PROBE}" cleanup \
  || fail "cleanup failed: $(cat "${SB}/verify.out")"
grep -q 'instances delete tee-e2e-rcv-1-1 ' "${SB}/gcloud-calls" \
  || fail "default receiver name changed: $(cat "${SB}/gcloud-calls")"
echo "ok   default receiver name tee-e2e-rcv-<suffix>"

suffix="locked-read-only-99999999999-1"
probe_with env RECEIVER_PREFIX=tee-attest-rcv RUN_SUFFIX="${suffix}" bash "${PROBE}" verify \
  || fail "verify with a prefix failed: $(cat "${SB}/verify.out")"
grep -q "get-serial-port-output tee-attest-rcv-${suffix} " "${SB}/gcloud-calls" \
  || fail "verify did not read the prefixed receiver: $(cat "${SB}/gcloud-calls")"
probe_with env RECEIVER_PREFIX=tee-attest-rcv RUN_SUFFIX="${suffix}" bash "${PROBE}" cleanup
for what in "instances delete" "firewall-rules delete"; do
  grep -q "${what} tee-attest-rcv-${suffix} " "${SB}/gcloud-calls" \
    || fail "cleanup did not run '${what}' on the prefixed receiver: $(cat "${SB}/gcloud-calls")"
done
echo "ok   RECEIVER_PREFIX names the receiver, its rule and its serial read"

# Matches the sweep's current-run patterns for the release's receivers.
sweep="${REPO_ROOT}/scripts/release/node-image-gcp/sweep-attestation-resources.sh"
# The literal `${GITHUB_RUN_ID}` in the sweep's source is what gets replaced.
# shellcheck disable=SC2016
inst_re="$(sed -n 's/^run_prefix_regex="\(.*\)"$/\1/p' "${sweep}" | sed 's/\${GITHUB_RUN_ID}/99999999999/')"
# shellcheck disable=SC2016
fw_re="$(sed -n 's/^run_firewall_regex="\(.*\)"$/\1/p' "${sweep}" | sed 's/\${GITHUB_RUN_ID}/99999999999/')"
[[ "tee-attest-rcv-${suffix}" =~ ${inst_re} ]] || fail "sweep instance regex ${inst_re} misses the release receiver"
[[ "tee-attest-rcv-${suffix}" =~ ${fw_re} ]] || fail "sweep firewall regex ${fw_re} misses the release receiver rule"
[[ "tdx-${suffix}" =~ ${inst_re} ]] || fail "sweep instance regex ${inst_re} no longer matches the node VM"
[[ "tee-attest-${suffix}" =~ ${fw_re} ]] || fail "sweep firewall regex ${fw_re} no longer matches the node rule"
echo "ok   the release's cleanup sweep matches its receiver and rule"

if probe_with env RECEIVER_PREFIX=tee-attest-rcv RUN_SUFFIX="$(printf 'x%.0s' $(seq 1 60))" bash "${PROBE}" cleanup; then
  fail "a receiver name over 63 characters was accepted"
fi
grep -q BAD_RECEIVER_NAME "${SB}/verify.out" || fail "an overlong name did not report BAD_RECEIVER_NAME"
[[ ! -s "${SB}/gcloud-calls" ]] || fail "gcloud ran with an invalid receiver name"
echo "ok   an invalid receiver name fails before any gcloud call"

# --- setup creates the receiver through gcp_create_instance -------------------
# The release runs setup for every profile, so one transient GCP error on the
# receiver create must be retried under the same name, not fail the release.
mkdir -p "${SB}/setup-bin"
cat > "${SB}/setup-bin/gcloud" <<STUB
#!/usr/bin/env bash
echo "\$*" >> "${SB}/setup-calls"
case "\$2 \$3" in
  "instances create")
    if [[ ! -e "${SB}/created-once" ]]; then
      touch "${SB}/created-once"
      echo "ERROR: (gcloud.compute.instances.create) Internal error. Please try again or contact Google Support." >&2
      exit 1
    fi
    exit 0 ;;
  "instances describe")
    [[ "\$*" == *networkIP* ]] && { echo 10.0.0.5; exit 0; }
    echo "ERROR: The resource '\$4' was not found" >&2; exit 1 ;;
esac
exit 0
STUB
chmod +x "${SB}/setup-bin/gcloud"
: > "${SB}/setup-calls"
: > "${SB}/gh-output"
(cd "${REPO_ROOT}" && PATH="${SB}/setup-bin:${PATH}" GCP_CREATE_RETRY_DELAY=0 \
  VM_PROJECT=p VM_ZONE=z VM_NETWORK=n VM_SUBNETWORK=s NODE_TAG=node-tag \
  IMAGE_PROFILE=debug-read-only RECEIVER_PREFIX=tee-attest-rcv RUN_SUFFIX="${suffix}" \
  TOKEN_FILE="${SB}/token" GITHUB_OUTPUT="${SB}/gh-output" \
  bash "${PROBE}" setup) > "${SB}/setup.out" 2>&1 \
  || fail "setup failed after one transient create error: $(cat "${SB}/setup.out")"
[[ "$(grep -c "^compute instances create tee-attest-rcv-${suffix} " "${SB}/setup-calls")" == "2" ]] \
  || fail "setup did not retry the receiver create under its name: $(cat "${SB}/setup-calls")"
for line in "receiver_name=tee-attest-rcv-${suffix}" "receiver_ip=10.0.0.5"; do
  grep -qx "${line}" "${SB}/gh-output" || fail "setup did not output ${line}: $(cat "${SB}/gh-output")"
done
[[ "$(stat -c '%a' "${SB}/token")" == "600" && -s "${SB}/token" ]] \
  || fail "the token file is missing or not mode 0600"
echo "ok   setup retries a transient receiver create under the same name"

# locked-read-only ships logs only over https (configure_vector.sh), so it can
# never push to the plain-http receiver: setup must say so at once, before it
# creates anything, rather than leave verify to time out after 600s.
for profile in locked-read-only some-new-profile; do
  : > "${SB}/setup-calls"
  if (cd "${REPO_ROOT}" && PATH="${SB}/setup-bin:${PATH}" \
    VM_PROJECT=p VM_ZONE=z VM_NETWORK=n VM_SUBNETWORK=s NODE_TAG=node-tag \
    IMAGE_PROFILE="${profile}" RUN_SUFFIX=1-1 \
    TOKEN_FILE="${SB}/token-${profile}" GITHUB_OUTPUT="${SB}/gh-output" \
    bash "${PROBE}" setup) > "${SB}/setup.out" 2>&1; then
    fail "setup accepted ${profile}, which refuses a plain-http logs endpoint"
  fi
  grep -q LOG_AUTH_UNSUPPORTED_PROFILE "${SB}/setup.out" \
    || fail "setup on ${profile} did not report LOG_AUTH_UNSUPPORTED_PROFILE: $(cat "${SB}/setup.out")"
  [[ ! -s "${SB}/setup-calls" && ! -e "${SB}/token-${profile}" ]] \
    || fail "setup on ${profile} touched GCP or wrote a token before refusing"
  echo "ok   setup refuses ${profile} before creating anything"
done

# The profiles setup accepts must be the ones configure_vector.sh lets ship
# over plain http; if that list changes, this check must change with it.
grep -qx '    debug|debug-read-only) ;;' "${REPO_ROOT}/mero-tee/ansible/roles/vector/files/configure_vector.sh" \
  || fail "configure_vector.sh's plain-http profile list changed; update node_log_auth_probe.sh setup and this test"
echo "ok   configure_vector.sh still allows plain http on debug and debug-read-only only"

# The KMS and agent releases run the same check, on the same profiles, because
# their init scripts read the same two keys and hand them to the same
# configure_vector.sh, pointing it at the profile their role pins.
for role in mero-kms:kms-init mero-agent:agent-init; do
  dir="${REPO_ROOT}/mero-tee/ansible/roles/${role%%:*}"
  init="${dir}/templates/${role#*:}.sh.j2"
  for want in 'get_meta logs-endpoint' 'get_meta observability-token' \
    "export OBS_PROFILE_FILE=/etc/${role%%:*}/image-profile" '/etc/vector/configure_vector.sh '; do
    grep -qF "${want}" "${init}" || fail "${role#*:} no longer has '${want}'; the log-auth check assumes it"
  done
  grep -qF "dest: /etc/${role%%:*}/image-profile" "${dir}/tasks/main.yml" \
    || fail "the ${role%%:*} role no longer writes /etc/${role%%:*}/image-profile"
done
echo "ok   kms-init and agent-init take the log keys and ship through configure_vector.sh"

# --- setup without a subnetwork puts the receiver on VM_NETWORK ---------------
# The KMS and agent probes create their VMs with neither --network nor --subnet,
# so on the `default` network's subnet in the zone's region. Their receiver must
# land there too: with VM_SUBNETWORK empty, setup passes --network and no
# --subnet. The node release, which passes a subnetwork, keeps --subnet.
touch "${SB}/created-once"
for case_ in subnet network; do
  : > "${SB}/setup-calls"
  subnet="s"
  [[ "${case_}" == network ]] && subnet=""
  (cd "${REPO_ROOT}" && PATH="${SB}/setup-bin:${PATH}" GCP_CREATE_RETRY_DELAY=0 \
    VM_PROJECT=p VM_ZONE=z VM_NETWORK=default VM_SUBNETWORK="${subnet}" NODE_TAG=kms-rel-debug-1-1 \
    IMAGE_PROFILE=debug RECEIVER_PREFIX=kms-attest-rcv RUN_SUFFIX=debug-1-1 \
    TOKEN_FILE="${SB}/token-${case_}" GITHUB_OUTPUT="${SB}/gh-output" \
    bash "${PROBE}" setup) > "${SB}/setup.out" 2>&1 \
    || fail "setup (${case_}) failed: $(cat "${SB}/setup.out")"
  create="$(grep '^compute instances create kms-attest-rcv-debug-1-1 ' "${SB}/setup-calls" || true)"
  if [[ "${case_}" == subnet ]]; then
    [[ "${create}" == *"--subnet s "* && "${create}" != *"--network "* ]] \
      || fail "setup with a subnetwork changed how it places the receiver: ${create}"
  else
    [[ "${create}" == *"--network default "* && "${create}" != *"--subnet"* ]] \
      || fail "setup without a subnetwork did not put the receiver on VM_NETWORK: ${create}"
  fi
done
grep -q -- '--network default .*--source-tags kms-rel-debug-1-1 .*--target-tags kms-attest-rcv-debug-1-1' "${SB}/setup-calls" \
  || fail "the receiver's rule does not admit the probe VM's tag on its network: $(cat "${SB}/setup-calls")"
echo "ok   without VM_SUBNETWORK the receiver joins VM_NETWORK, as the KMS and agent VMs do"

# --- the KMS and agent probes give their VM the two log keys -------------------
# log_auth_metadata.sh turns LOGS_ENDPOINT and OBSERVABILITY_TOKEN_FILE into the
# `logs-endpoint` and `observability-token` keys. Neither is measured; without
# them a probe VM's metadata must stay exactly what it was.
HELPER="${REPO_ROOT}/scripts/ci/probes/log_auth_metadata.sh"
printf 'abc123' > "${SB}/obs-token"
printf 'a,b' > "${SB}/bad-token"
meta() {
  # shellcheck source=scripts/ci/probes/log_auth_metadata.sh
  (source "${HELPER}" && LOGS_ENDPOINT="$1" OBSERVABILITY_TOKEN_FILE="$2" log_auth_metadata) 2>"${SB}/meta.err"
}
[[ "$(meta "" "")" == "" ]] || fail "log_auth_metadata printed keys with no endpoint"
got="$(meta "http://10.0.0.5:9200" "${SB}/obs-token" || true)"
[[ "${got}" == ",logs-endpoint=http://10.0.0.5:9200,observability-token=abc123" ]] \
  || fail "log_auth_metadata printed '${got}': $(cat "${SB}/meta.err")"
for bad in "http://10.0.0.5:9200|" "|${SB}/obs-token" "http://10.0.0.5:9200,x=y|${SB}/obs-token" \
  "http://10.0.0.5:9200|${SB}/bad-token" "http://10.0.0.5:9200|${SB}/missing-token"; do
  if meta "${bad%%|*}" "${bad#*|}" >/dev/null; then
    fail "log_auth_metadata accepted '${bad}'"
  fi
done
echo "ok   log_auth_metadata prints both keys, nothing, or refuses"

# Each probe runs against a stub gcloud whose `instances create` records its
# arguments and fails, so the probe stops at its first VM, as a real create
# failure would, and its trap cleans up.
mkdir -p "${SB}/vm-bin"
cat > "${SB}/vm-bin/gcloud" <<STUB
#!/usr/bin/env bash
echo "\$*" >> "${SB}/vm-calls"
if [[ "\$2 \$3" == "instances create" ]]; then
  echo "ERROR: (gcloud.compute.instances.create) Invalid value for field" >&2
  exit 1
fi
exit 0
STUB
cat > "${SB}/vm-bin/curl" <<'STUB'
#!/usr/bin/env bash
echo 192.0.2.1
STUB
chmod +x "${SB}/vm-bin/gcloud" "${SB}/vm-bin/curl"
run_vm_probe() {
  local script="$1"; shift
  : > "${SB}/vm-calls"
  (cd "${REPO_ROOT}" && env PATH="${SB}/vm-bin:${PATH}" IMAGE=img IMAGE_PROJECT=ip PROFILE=debug \
    PROBE_NAME=probe-debug-1-1 VM_PROJECT=p VM_ZONE=z VM_MACHINE_TYPE=m ITA_API_KEY=k \
    OUT_DIR="${SB}/vm-out" PROVISION_MODE=skip "$@" bash "${script}") > "${SB}/vm.out" 2>&1 || true
  grep -m1 '^compute instances create ' "${SB}/vm-calls" || true
}
for probe in "scripts/release/kms/run-cluster-probe.sh|kms-bootstrap=true" \
  "scripts/release/agent/run-agent-probe.sh|ephemeral-store=true"; do
  script="${REPO_ROOT}/${probe%%|*}" base="${probe#*|}"
  create="$(run_vm_probe "${script}")"
  [[ "${create}" == *"--metadata ${base} "* ]] \
    || fail "${probe%%|*} changed its VM's metadata without the check: ${create} $(cat "${SB}/vm.out")"
  create="$(run_vm_probe "${script}" LOGS_ENDPOINT=http://10.0.0.5:9200 OBSERVABILITY_TOKEN_FILE="${SB}/obs-token")"
  [[ "${create}" == *"--metadata ${base},logs-endpoint=http://10.0.0.5:9200,observability-token=abc123 "* ]] \
    || fail "${probe%%|*} did not give its VM the two log keys: ${create} $(cat "${SB}/vm.out")"
  run_vm_probe "${script}" LOGS_ENDPOINT=http://10.0.0.5:9200 >/dev/null
  [[ ! -s "${SB}/vm-calls" ]] || fail "${probe%%|*} touched GCP with a half-set log-auth check: $(cat "${SB}/vm-calls")"
  echo "ok   ${probe%%|*} passes the log keys to its VM, and only when asked"
done

# The release names its receivers <kms|agent>-attest-rcv-<profile>-<run>-<attempt>.
# The longest must be a valid GCE name, and the node release's sweep must catch
# one a lost runner left behind (its stale patterns, after the max age).
long="agent-attest-rcv-debug-read-only-99999999999-99"
(( ${#long} <= 63 )) || fail "${long} is over 63 characters"
stale_inst_re="$(sed -n 's/^stale_prefix_regex="\(.*\)"$/\1/p' "${sweep}")"
stale_fw_re="$(sed -n 's/^stale_firewall_regex="\(.*\)"$/\1/p' "${sweep}")"
for name in kms-attest-rcv-debug-12345-1 agent-attest-rcv-debug-read-only-12345-2 \
  tee-attest-rcv-debug-12345-1; do
  [[ "${name}" =~ ${stale_inst_re} ]] || fail "sweep stale instance regex ${stale_inst_re} misses ${name}"
  [[ "${name}" =~ ${stale_fw_re} ]] || fail "sweep stale firewall regex ${stale_fw_re} misses ${name}"
done
[[ "tdx-debug-12345-1" =~ ${stale_inst_re} && "tee-attest-debug-12345-1" =~ ${stale_fw_re} ]] \
  || fail "the sweep's stale patterns no longer match the node VM and its rule"
for name in kms-rel-debug-12345-1 kms-attest-debug-12345-1 agent-rel-debug-12345-1; do
  [[ ! "${name}" =~ ${stale_inst_re} && ! "${name}" =~ ${stale_fw_re} ]] \
    || fail "the sweep's stale patterns match ${name}, which is not a receiver"
done
echo "ok   the node release's sweep also catches stale KMS and agent receivers"

echo "== log-auth probe classifies pushes and verdicts correctly =="
