#!/usr/bin/env bash
# A first boot serves its release attestation, and waits for the cluster's KMS
# identity, before it initialises merod.
#
# Stamping `kms-identity` on an instance releases the cluster's storage key to
# it, so mdma does that only after verifying the node's release attestation
# (`merod attest --serve`, GET <public-url>/attestation/release). calimero-init
# must therefore, on a locked-read-only first boot with a cluster and no
# identity yet: serve the attestation on merod's own listen address, start
# traefik ahead of its After=calimero-init ordering, long-poll the metadata
# server until kms-identity appears, stop the server (SIGTERM, reaped) and only
# then install the identity and run `merod init`.
#
# Like the store-encryption test this one EXECUTES the decision block sliced out
# of the template, here against a mock GCE metadata server, a stub merod that
# records how it was served and signalled, and a stub systemctl:
#
#   * merod with attest, no identity yet -> serve, traefik early, long-poll,
#     identity appears -> serve stopped and reaped BEFORE merod init, identity
#     installed 0600 and never logged
#   * merod without attest              -> today's behaviour: read once, no serve
#   * identity already stamped          -> no serve, no wait
#   * identity never stamped            -> the boot fails after kms-identity-wait-sec,
#                                          the server stopped, nothing initialised
#   * metadata server errors            -> backoff, then the identity is installed
#   * a server ignoring SIGTERM         -> killed, merod init still runs
#   * a node already initialised, or one whose identity is installed -> no gate
#   * debug profile / memory-only store -> no gate (identity not required)
#   * a malformed kms-identity-wait-sec -> refused
#
# Usage: scripts/ci/tests/kms-identity-attest-gate-test.sh
# shellcheck disable=SC2016
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ROLE="${REPO_ROOT}/mero-tee/ansible/roles/merotee"
TEMPLATE="${ROLE}/templates/calimero-init.sh.j2"
TASKS="${ROLE}/tasks/main.yml"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok: $*"; }
[[ -r "$TEMPLATE" ]] || fail "cannot read ${TEMPLATE}"

WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  [[ -z "$SERVER_PID" ]] || kill "$SERVER_PID" 2>/dev/null || true
  pkill -f "$WORK/" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- slice the code under test out of the template --------------------------
init_fn="$(awk '/^INIT_EXTRA_ARGS=\(\)$/,/^}$/' "$TEMPLATE")"
decision="$(awk '/^NODE_CONFIG="\$CALIMERO_HOME\/\$CALIMERO_NODE\/config.toml"$/{on=1} /^log "Starting services\.\.\."$/{exit} on{print}' "$TEMPLATE")"
[[ -n "$init_fn" ]] || fail "could not find init_node / INIT_EXTRA_ARGS in the template"
[[ -n "$decision" ]] || fail "could not find the merod block (NODE_CONFIG=... up to 'Starting services') in the template"
grep -qF '    kms_identity_gate' <<<"$decision" || fail "the merod decision does not call kms_identity_gate"
grep -qF 'kms_identity_gate() {' <<<"$decision" || fail "kms_identity_gate is not defined in the sliced block"

# The server takes merod's own port, which traefik routes every path to.
listen="$(sed -n 's/^ATTEST_LISTEN="\(.*\)"$/\1/p' "$TEMPLATE")"
merod_listen="$(sed -n 's/.*Environment=MEROD_LISTEN=\([^[:space:]]*\).*/\1/p' "$TASKS" | head -1)"
[[ -n "$listen" && "$listen" == "$merod_listen" ]] \
  || fail "ATTEST_LISTEN ($listen) must be merod.service's MEROD_LISTEN ($merod_listen), traefik's upstream"
# traefik keeps its ordering after calimero-init; the gate starts it explicitly.
grep -qF 'After=calimero-init.service' <<<"$(awk '/Drop-in for traefik to run after calimero-init/,/dest:/' "$TASKS")" \
  || fail "traefik must stay ordered after calimero-init"
pass "the gate serves on merod's listen address ($listen), traefik's upstream"

# --- the mock GCE metadata server --------------------------------------------
# /<case>/computeMetadata/v1/instance/attributes/<key>: $META/<case>/<key>, 404
# when absent; 503 while $META/<case>/.fail-kms holds a positive count (for
# kms-identity only). The directory (`attributes/?recursive=true`) answers with
# ETag = hash of every attribute; wait_for_change with that ETag as last_etag
# waits (timeout_sec, capped at 2s) for a change. Every request is logged.
META="$WORK/meta"
mkdir -p "$META"
cat >"$WORK/server.py" <<'PY'
import hashlib, json, os, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

root = sys.argv[1]
ATTRS = "/computeMetadata/v1/instance/attributes/"

def snapshot(d):
    out = {}
    for name in sorted(os.listdir(d)):
        if not name.startswith("."):
            with open(os.path.join(d, name), "rb") as f:
                out[name] = f.read().decode()
    return out, hashlib.sha256(json.dumps(out).encode()).hexdigest()[:16]

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, body=b"", etag=None):
        self.send_response(code)
        if etag:
            self.send_header("ETag", etag)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.headers.get("Metadata-Flavor") != "Google":
            return self.reply(403)
        url = urlsplit(self.path)
        case, _, rest = url.path.lstrip("/").partition("/")
        rest = "/" + rest
        d = os.path.join(root, case)
        if not rest.startswith(ATTRS) or not os.path.isdir(d):
            return self.reply(404)
        with open(os.path.join(d, ".requests"), "a") as f:
            f.write(rest[len(ATTRS):] + ("?" + url.query if url.query else "") + "\n")
        key = rest[len(ATTRS):]
        q = parse_qs(url.query)
        if key == "":
            body, etag = snapshot(d)
            if q.get("wait_for_change") == ["true"] and q.get("last_etag", [""])[0] == etag:
                deadline = time.time() + min(2.0, float(q.get("timeout_sec", ["2"])[0]))
                while time.time() < deadline:
                    time.sleep(0.1)
                    body, now = snapshot(d)
                    if now != etag:
                        etag = now
                        break
            return self.reply(200, json.dumps(body).encode(), etag)
        if key == "kms-identity":
            fk = os.path.join(d, ".fail-kms")
            if os.path.exists(fk):
                n = int(open(fk).read() or "0")
                if n > 0:
                    open(fk, "w").write(str(n - 1))
                    return self.reply(503)
        try:
            with open(os.path.join(d, key), "rb") as f:
                body = f.read()
        except (FileNotFoundError, IsADirectoryError):
            return self.reply(404)
        self.reply(200, body, hashlib.sha256(body).hexdigest()[:16])

srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
with open(os.path.join(root, ".port"), "w") as f:
    f.write(str(srv.server_address[1]))
srv.serve_forever()
PY
python3 "$WORK/server.py" "$META" &
SERVER_PID=$!
for _ in $(seq 50); do [[ -s "$META/.port" ]] && break; sleep 0.1; done
[[ -s "$META/.port" ]] || fail "the mock metadata server did not start"
PORT="$(cat "$META/.port")"
export no_proxy="127.0.0.1,localhost" NO_PROXY="127.0.0.1,localhost"

# kms_identity: base64 of a protobuf libp2p Ed25519 keypair, as mdma stamps it.
kms_identity() {
  python3 - <<'PY'
import base64, os, subprocess
secret = os.urandom(32)
der = bytes.fromhex("302e020100300506032b657004220420") + secret
pub = subprocess.run(["openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"],
                     input=der, capture_output=True, check=True).stdout[-32:]
print(base64.b64encode(bytes([8, 1, 0x12, 0x40]) + secret + pub).decode(), end="")
PY
}
ID="$(kms_identity)"
URL="https://kms.example:8080/"

# run_case NAME PROFILE MEROD(attest|stubborn|old) HOME(fresh|existing|identity) STORE_FS MDMA [KEY=VALUE...]
# MDMA: `none`, or `after` (stamp kms-identity 1.5s after the server starts).
run_case() {
  local name="$1" profile="$2" merod="$3" home_state="$4" store_fs="$5" mdma="$6"
  shift 6
  local dir="$WORK/$name"
  mkdir -p "$dir/bin" "$dir/mnt/data/merod" "$META/$name"
  local kv
  for kv in "$@"; do [[ -n "$kv" ]] && printf '%s' "${kv#*=}" >"$META/$name/${kv%%=*}"; done

  cat >"$dir/bin/merod" <<STUB
#!/usr/bin/env bash
if [[ " \$* " == *" attest "* ]]; then
  [[ "$merod" != old ]] || { echo "error: unrecognized subcommand 'attest'" >&2; exit 2; }
  if [[ " \$* " == *" --help "* ]]; then
    echo "Usage: merod attest [OPTIONS]"
    echo "      --serve <SERVE>"
    exit 0
  fi
  printf '%s\n' "\$@" >"$dir/serve-args"
  printf '%s\n' "\${MERO_TEE_VERSION:-}" >"$dir/serve-release"
  echo \$\$ >"$dir/serve-pid"
  if [[ "$merod" == stubborn ]]; then
    trap 'echo TERM >>"$dir/serve-signals"' TERM
  else
    trap 'echo TERM >>"$dir/serve-signals"; exit 0' TERM
  fi
  while :; do sleep 0.1; done
fi
if [[ " \$* " == *" --help "* ]]; then
  echo "Usage: merod init [OPTIONS]"
  echo "      --kms-url <URL>"
  echo "      --node-id <N>"
  echo "      --kms-identity <FILE>"
  exit 0
fi
[[ " \$* " == *" init "* ]] || exit 0
printf '%s\n' "\$@" >"$dir/init-args"
if [[ -s "$dir/serve-pid" ]] && kill -0 "\$(cat "$dir/serve-pid")" 2>/dev/null; then
  echo yes >"$dir/serve-alive-at-init"
else
  echo no >"$dir/serve-alive-at-init"
fi
STUB
  cat >"$dir/bin/systemctl" <<STUB
#!/usr/bin/env bash
echo "\$*" >>"$dir/systemctl.log"
STUB
  printf '#!/usr/bin/env bash\necho %s\n' "$store_fs" >"$dir/bin/findmnt"
  printf '#!/usr/bin/env bash\nexit 0\n' >"$dir/bin/swapon"
  chmod +x "$dir/bin/merod" "$dir/bin/systemctl" "$dir/bin/findmnt" "$dir/bin/swapon"

  case "$home_state" in
    fresh) ;;
    existing) mkdir -p "$dir/mnt/data/merod/default"
              printf 'node-id = 1\n' >"$dir/mnt/data/merod/default/config.toml" ;;
    identity) printf '%s' "$ID" | base64 -d >"$dir/mnt/data/merod/kms-identity" ;;
  esac

  local mdma_pid=""
  if [[ "$mdma" == after ]]; then
    (
      for _ in $(seq 100); do [[ -s "$dir/serve-pid" ]] && break; sleep 0.1; done
      sleep 1.5
      printf '%s' "$ID" >"$META/$name/kms-identity"
    ) &
    mdma_pid=$!
  fi

  cat >"$dir/run.sh" <<RUN
set -euo pipefail
LOG="$dir/log"
log() { echo "\$*" >>"$dir/log"; }
fatal() { log "ERROR: \$*"; exit 1; }
stage() { echo "\$1: \$2" >>"$dir/stages"; }
disk_secrets_cleanup() { :; }
METADATA_URL="http://127.0.0.1:${PORT}/${name}/computeMetadata/v1/instance/attributes"
METADATA_HEADER="Metadata-Flavor: Google"
get_meta() { curl -sf -H "\$METADATA_HEADER" "\${METADATA_URL}/\$1" 2>/dev/null || true; }
export MERO_TEE_VERSION=2.4.0
PATH="$dir/bin:\$PATH"
BIN_DIR="$dir/bin"
CALIMERO_HOME="$dir/mnt/data/merod"
CALIMERO_NODE="default"
IMAGE_PROFILE="$profile"
KMS_URL="$URL"
JOB_NODE=""
TEE_RELEASE_VERSION=2.4.0
ATTEST_STOP_TIMEOUT=1
$init_fn
$decision
echo "\$MEROD_READY" >"$dir/ready"
RUN
  local start=$SECONDS
  set +e
  bash "$dir/run.sh" >/dev/null 2>&1
  echo $? >"$dir/rc"
  set -e
  echo $((SECONDS - start)) >"$dir/elapsed"
  [[ -z "$mdma_pid" ]] || wait "$mdma_pid" 2>/dev/null || true
}

rc() { cat "$WORK/$1/rc"; }
elapsed() { cat "$WORK/$1/elapsed"; }
served() { [[ -f "$WORK/$1/serve-args" ]]; }
init_ran() { [[ -f "$WORK/$1/init-args" ]]; }
logged() { grep -qF "$2" "$WORK/$1/log" 2>/dev/null; }
requests() { cat "$META/$1/.requests" 2>/dev/null || true; }
serve_running() {
  local pid
  pid="$(cat "$WORK/$1/serve-pid" 2>/dev/null)" || return 1
  kill -0 "$pid" 2>/dev/null
}
installed() { cmp -s "$WORK/$1/mnt/data/merod/kms-identity" <(printf '%s' "$ID" | base64 -d); }

BASE=(node-id=1 "public-url=https://n1.eu1.example.com/" cluster=eu1)

# --- the gate: serve, traefik, long-poll, stop, then init --------------------
run_case gate locked-read-only attest fresh ext4 after "${BASE[@]}"
[[ "$(rc gate)" == 0 ]] || fail "a first boot whose identity mdma stamps after attesting it should initialise (rc=$(rc gate)): $(cat "$WORK/gate/log")"
served gate || fail "merod attest --serve was not started on a first boot without kms-identity"
[[ "$(tr '\n' ' ' <"$WORK/gate/serve-args")" == "--home $WORK/gate/mnt/data/merod --node default attest --serve 127.0.0.1:2528 " ]] \
  || fail "merod attest was not run as 'merod --home H --node default attest --serve 127.0.0.1:2528': $(tr '\n' ' ' <"$WORK/gate/serve-args")"
[[ "$(cat "$WORK/gate/serve-release")" == 2.4.0 ]] || fail "MERO_TEE_VERSION did not reach merod attest"
grep -qx 'start --job-mode=ignore-dependencies traefik' "$WORK/gate/systemctl.log" 2>/dev/null \
  || fail "traefik was not started ahead of its After=calimero-init ordering while serving"
requests gate | grep -qE '^\?recursive=true&wait_for_change=true&timeout_sec=[0-9]+&last_etag=[0-9a-f]{16}$' \
  || fail "the wait did not long-poll the attributes directory by ETag: $(requests gate | tr '\n' ' ')"
[[ "$(grep -cx 'TERM' "$WORK/gate/serve-signals" 2>/dev/null)" == 1 ]] || fail "the attest server was not sent SIGTERM once"
[[ "$(cat "$WORK/gate/serve-alive-at-init")" == no ]] || fail "merod init ran while the attest server still held the port"
serve_running gate && fail "the attest server is still running after the boot"
init_ran gate || fail "merod init did not run after kms-identity appeared"
installed gate || fail "the kms-identity that appeared was not installed"
[[ "$(stat -c %a "$WORK/gate/mnt/data/merod/kms-identity")" == 600 ]] || fail "the installed identity is not 0600"
grep -qF "${ID:0:24}" "$WORK/gate/log" && fail "the KMS identity value reached the log"
logged gate "stopped the release attestation server" || fail "stopping the server was not logged"
pass "a first boot serves its release attestation, waits for kms-identity, and stops serving before merod init"

# --- an older merod: no attest, today's behaviour -----------------------------
run_case old_absent locked-read-only old fresh ext4 none "${BASE[@]}"
[[ "$(rc old_absent)" != 0 ]] || fail "an old merod with no kms-identity on a locked cluster must still refuse"
served old_absent && fail "a merod without attest was asked to serve"
logged old_absent "no kms-identity metadata. Every node of cluster" || fail "the old refusal did not fire: $(cat "$WORK/old_absent/log")"
(( $(elapsed old_absent) < 5 )) || fail "an old merod must not wait for kms-identity ($(elapsed old_absent)s)"
run_case old_present locked-read-only old fresh ext4 none "${BASE[@]}" "kms-identity=$ID"
if ! { [[ "$(rc old_present)" == 0 ]] && init_ran old_present && installed old_present; }; then
  fail "an old merod with kms-identity stamped should initialise as before: $(cat "$WORK/old_present/log")"
fi
served old_present && fail "a merod without attest was asked to serve"
pass "a merod without 'attest --serve' reads kms-identity once, as before"

# --- already stamped: nothing to gate ------------------------------------------
run_case present locked-read-only attest fresh ext4 none "${BASE[@]}" "kms-identity=$ID"
if ! { [[ "$(rc present)" == 0 ]] && init_ran present && installed present; }; then
  fail "a first boot with kms-identity already stamped should initialise: $(cat "$WORK/present/log")"
fi
served present && fail "the server was started though kms-identity was already set"
pass "kms-identity already stamped: no server, no wait"

# --- never stamped: the boot fails after kms-identity-wait-sec ---------------
run_case timeout locked-read-only attest fresh ext4 none "${BASE[@]}" kms-identity-wait-sec=2
[[ "$(rc timeout)" != 0 ]] || fail "a first boot whose identity never comes must fail"
logged timeout "ERROR: no kms-identity metadata after 2s" || fail "the timeout was not reported clearly: $(cat "$WORK/timeout/log")"
init_ran timeout && fail "merod init ran without the cluster identity"
[[ -e "$WORK/timeout/mnt/data/merod/kms-identity" ]] && fail "an identity file was written on timeout"
grep -qx TERM "$WORK/timeout/serve-signals" 2>/dev/null || fail "the attest server was not stopped on timeout"
serve_running timeout && fail "the attest server outlived a failed boot"
(( $(elapsed timeout) < 10 )) || fail "kms-identity-wait-sec=2 was not honoured ($(elapsed timeout)s)"
pass "an identity that never comes fails the boot after kms-identity-wait-sec, with the server stopped"

# --- a flaky metadata server: backoff, then install ---------------------------
mkdir -p "$META/flaky"; echo 2 >"$META/flaky/.fail-kms"
run_case flaky locked-read-only attest fresh ext4 after "${BASE[@]}"
if ! { [[ "$(rc flaky)" == 0 ]] && init_ran flaky && installed flaky; }; then
  fail "metadata errors while waiting must be retried: $(cat "$WORK/flaky/log")"
fi
logged flaky "WARN: metadata server answered 503 while waiting for kms-identity" || fail "a metadata error was not logged"
pass "metadata server errors while waiting are retried with backoff"

# --- a server that ignores SIGTERM is killed ----------------------------------
run_case stubborn locked-read-only stubborn fresh ext4 after "${BASE[@]}"
if ! { [[ "$(rc stubborn)" == 0 ]] && init_ran stubborn; }; then
  fail "a stubborn attest server must not block the boot: $(cat "$WORK/stubborn/log")"
fi
[[ "$(cat "$WORK/stubborn/serve-alive-at-init")" == no ]] || fail "merod init ran while the stubborn server was alive"
logged stubborn "did not stop within 1s of SIGTERM; killing it" || fail "killing the server was not logged"
pass "an attest server that ignores SIGTERM is killed before merod init"

# --- later boots, and nodes that do not need the cluster identity -------------
run_case second locked-read-only attest existing ext4 none "${BASE[@]}"
if ! { [[ "$(rc second)" == 0 && "$(cat "$WORK/second/ready")" == true ]]; }; then
  fail "an initialised node must start: $(cat "$WORK/second/log")"
fi
served second && fail "an initialised node served its release attestation again"
init_ran second && fail "an initialised node was initialised again"
[[ -z "$(requests second | grep -F kms-identity || true)" ]] || fail "an initialised node read kms-identity"
run_case installed locked-read-only attest identity ext4 none "${BASE[@]}" "kms-identity=$ID"
if ! { [[ "$(rc installed)" == 0 ]] && init_ran installed; }; then
  fail "a node whose identity is installed should initialise"
fi
served installed && fail "a node whose identity is installed served its release attestation"
pass "a later boot (configured, or identity installed) skips the gate"

run_case debug debug-read-only attest fresh ext4 none "${BASE[@]}"
if ! { [[ "$(rc debug)" == 0 ]] && init_ran debug; }; then
  fail "a debug node without kms-identity should initialise as before"
fi
served debug && fail "a debug node, where the identity is optional, waited for it"
run_case memory locked-read-only attest fresh tmpfs none "${BASE[@]}"
if ! { [[ "$(rc memory)" == 0 ]] && init_ran memory; }; then
  fail "a memory-only node without kms-identity should initialise as before"
fi
served memory && fail "a memory-only node, where the identity is optional, waited for it"
pass "debug profiles and memory-only stores keep reading kms-identity once"

run_case badwait locked-read-only attest fresh ext4 none "${BASE[@]}" kms-identity-wait-sec=soon
if ! { [[ "$(rc badwait)" != 0 ]] && logged badwait "'kms-identity-wait-sec' is not a number"; }; then
  fail "a malformed kms-identity-wait-sec must be refused"
fi
served badwait && fail "a malformed kms-identity-wait-sec still started the server"
pass "a malformed kms-identity-wait-sec is refused"

echo "PASS: the cluster KMS identity is installed only after the node served its release attestation"
