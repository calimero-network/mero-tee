#!/usr/bin/env bash
# The release and staging probes measure a merod 1.0 image from its release
# attestation (`merod attest --serve`, GET /attestation/release?nonce=), since
# the probe VM has no KMS and merod 1.0 does not run without one. This pins,
# without any cloud, what could make those probes lie or break:
#
#   * node_release_attestation.sh writes tee-attest-response.json with
#     `quoteB64` (what the verifiers read) and tee-info.json with the node's
#     MRTD, from an answer over our nonce
#   * it refuses a mock quote, a quote over another nonce, and non-JSON
#   * it exits 2 (the caller dumps the serial console) when nothing answers
#   * node_anti_fake_http.py reads REPORTDATA from the quote bytes (v4 and v5),
#     not from the node's copy, and fetches with GET
#
# Usage: scripts/ci/tests/node-release-attestation-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROBE="${REPO_ROOT}/scripts/ci/probes/node_release_attestation.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }

WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() { [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

# A fake node: answers /attestation/release with a v4 quote whose REPORTDATA
# starts with the requested nonce. MODE (a file) bends the answer.
cat >"$WORK/node.py" <<'PY'
import base64, json, sys, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

work = sys.argv[1]

def quote(nonce_hex):
    q = bytearray(1024)
    q[0] = 4  # version 4, little endian
    mrtd = 184
    q[mrtd:mrtd + 48] = b"\x11" * 48
    rd = mrtd + 48 + 7 * 48
    q[rd:rd + 32] = bytes.fromhex(nonce_hex)
    q[rd + 32:rd + 64] = b"\x22" * 32
    return base64.b64encode(bytes(q)).decode()

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path != "/attestation/release":
            self.send_response(404); self.end_headers(); return
        mode = open(f"{work}/mode").read().strip()
        nonce = urllib.parse.parse_qs(u.query)["nonce"][0]
        if mode == "notjson":
            body = b"<html>bad gateway</html>"
        else:
            if mode == "othernonce":
                nonce = "ab" * 32
            env = {
                "format": 1,
                "quote": quote(nonce),
                "nonce": nonce,
                "claim": {"merodVersion": "1.0.0-rc.2", "merodSha256": "00" * 32,
                          "teeRelease": None, "teeProfile": "debug", "identity": None},
                "reportData": "",
                "reportDataLayout": "nonce(32) || release_binding(32)",
                "measurements": None if mode == "mock" else {
                    "mrtd": "11" * 48, "rtmr0": "00" * 48, "rtmr1": "00" * 48,
                    "rtmr2": "00" * 48, "rtmr3": "00" * 48},
                "mock": mode == "mock",
            }
            body = json.dumps(env).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

srv = HTTPServer(("127.0.0.1", 0), H)
open(f"{work}/port", "w").write(str(srv.server_port))
srv.serve_forever()
PY
echo ok >"$WORK/mode"
python3 "$WORK/node.py" "$WORK" &
SERVER_PID=$!
for _ in $(seq 1 50); do [[ -s "$WORK/port" ]] && break; sleep 0.1; done
[[ -s "$WORK/port" ]] || fail "the fake node did not start"
BASE="http://127.0.0.1:$(cat "$WORK/port")"

# run MODE NAME: run the probe against the fake node; prints its exit code.
run() {
  echo "$1" >"$WORK/mode"
  mkdir -p "$WORK/$2"
  set +e
  CI_LOG_VERBOSITY=compact bash "$PROBE" "$BASE" "$WORK/$2" 20 >"$WORK/$2/out" 2>&1
  echo $?
  set -e
}

# --- a release attestation over our nonce --------------------------------------
[[ "$(run ok ok)" == 0 ]] || fail "a good answer was refused: $(cat "$WORK/ok/out")"
nonce="$(jq -r .nonce "$WORK/ok/tee-attest-request.json")"
[[ "$nonce" =~ ^[0-9a-f]{64}$ ]] || fail "the request must carry a 32-byte hex nonce, got '$nonce'"
jq -e '.quoteB64 == .quote and (.quoteB64 | length > 0)' "$WORK/ok/tee-attest-response.json" >/dev/null \
  || fail "tee-attest-response.json must carry quoteB64 for the verifiers"
[[ "$(jq -r .data.mrtd "$WORK/ok/tee-info.json")" == "$(printf '11%.0s' $(seq 48))" ]] \
  || fail "tee-info.json must carry the node's MRTD as data.mrtd"
jq -e '.claim.merodVersion == "1.0.0-rc.2"' "$WORK/ok/tee-info.json" >/dev/null || fail "tee-info.json must carry the claim"

# The verifiers find the quote where they look for it.
python3 - "$REPO_ROOT" "$WORK/ok/tee-attest-response.json" <<'PY' || fail "verify_tdx_quote_ita.py does not find the quote"
import json, sys
sys.path.insert(0, f"{sys.argv[1]}/scripts/attestation/shared")
from verify_tdx_quote_ita import quote_b64_from_attest_json
quote, path = quote_b64_from_attest_json(json.load(open(sys.argv[2])))
assert quote and path == "$.quoteB64", path
PY

# --- answers that are not a release attestation of real hardware for us --------
[[ "$(run mock mock)" == 1 ]] || fail "a mock quote must be refused"
[[ "$(run othernonce othernonce)" == 1 ]] || fail "a quote over another nonce must be refused"
[[ "$(run notjson notjson)" == 1 ]] || fail "a non-JSON answer must be refused"
[[ ! -f "$WORK/mock/tee-attest-response.json" ]] || fail "a refused answer must not be handed to the verifiers"

# --- nothing answers ------------------------------------------------------------
mkdir -p "$WORK/down"
set +e
CI_LOG_VERBOSITY=compact bash "$PROBE" "http://127.0.0.1:9" "$WORK/down" 6 >"$WORK/down/out" 2>&1
down=$?
set -e
[[ "$down" == 2 ]] || fail "no answer must exit 2 (the caller dumps the serial console), got $down"

# --- the anti-fake probe reads REPORTDATA from the quote ------------------------
echo ok >"$WORK/mode"
python3 - "$REPO_ROOT" "$BASE" <<'PY' || fail "node_anti_fake_http.py does not read the release attestation"
import base64, json, sys
sys.path.insert(0, f"{sys.argv[1]}/scripts/ci/probes")
sys.path.insert(0, f"{sys.argv[1]}/scripts/attestation/shared")
import node_anti_fake_http as af

nonce = "5a" * 32
status, body = af.attest(sys.argv[2], nonce, 10)
assert status == 200, status
quote = base64.b64decode(json.loads(body)["quote"])
rd = af.report_data_of(quote)
assert rd is not None and rd[:64] == nonce, rd
# v5: the body starts 6 bytes later (its type and size after the header).
v5 = bytearray(quote[:48]) + bytearray(6) + bytearray(quote[48:])
v5[0:2] = (5).to_bytes(2, "little")
assert af.report_data_of(bytes(v5))[:64] == nonce
assert af.report_data_of(b"\x03\x00" + bytes(1000)) is None, "an unknown version must not be read"
assert af.report_data_of(b"\x04\x00" + bytes(100)) is None, "a short quote must not be read"
PY

echo "PASS: the probes read merod 1.0's release attestation and refuse anything else"
