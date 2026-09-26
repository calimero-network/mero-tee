#!/usr/bin/env bash
# The staging probe's Secret Manager fetch check must tell a fetched credential
# apart from a failed fetch.
#
# The check itself runs only on real GCP (node-image-gcp-staging-probe.yaml,
# `secret_fetch_check`). Two pieces of it can be wrong without any cloud, and a
# wrong one would make that run lie:
#
#   * log_auth_receiver.py must classify each push as OK only when the bearer
#     token hashes to the expected SHA-256. A receiver that passed any token,
#     or no token at all, would turn a failed fetch into a green check.
#   * `node_secret_fetch_probe.sh verify` must pass on an authenticated push,
#     and on anything else fail with the code that names what went wrong.
#
# Here the receiver runs on localhost and gets real HTTP requests, and verify
# reads its output through a stub `gcloud` that plays the serial console.
#
# Usage: scripts/ci/tests/node-secret-fetch-probe-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RECEIVER="${REPO_ROOT}/scripts/ci/probes/log_auth_receiver.py"
PROBE="${REPO_ROOT}/scripts/ci/probes/node_secret_fetch_probe.sh"

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
    jq -e '.passed == true' "${SB}/art/node-secret-fetch-result.json" >/dev/null \
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
  'PROBE_RECEIVER_READY port=9200\nPROBE_AUTH_NONE POST /_bulk\n' SECRET_FETCH_FAILED
expect_verify "a wrong token" \
  'PROBE_RECEIVER_READY port=9200\nPROBE_AUTH_MISMATCH POST /_bulk\n' SECRET_FETCH_WRONG_TOKEN
expect_verify "a receiver that never started" \
  'boot\n' RECEIVER_NOT_READY
expect_verify "no pushes at all" \
  'PROBE_RECEIVER_READY port=9200\n' NO_LOG_PUSHES

echo "== secret-fetch probe classifies pushes and verdicts correctly =="
