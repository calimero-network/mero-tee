#!/usr/bin/env bash
# The node asks mdma for a certificate for its in-enclave TLS key, and installs
# only one for that key.
#
# mdma (dispatcher/app/node_certs.py) reads the guest attributes calimero/tls-csr
# and calimero/tls-quote, orders a certificate only when the CSR names exactly
# the node's public-url host (and *.<apps-domain>) and the quote's report data is
# SHA-256(CSR) || SHA-256("calimero.tee-attest.tls-csr.v1"), and writes the
# chain back as instance metadata tls-cert. The host can write that metadata
# too. This runs mero-tee/ansible/roles/merotee/files/calimero-tls-cert.sh, the
# tool the image installs, against a mock metadata server, a mock configfs-tsm
# report directory and a stub systemctl, and checks:
#
#   * the CSR's names: exactly the host (lowercased, port, path and userinfo
#     gone) and *.<apps-domain> when set; DNS names only, CN the host, a valid
#     self-signature over key.pem; nothing published for a non-https URL
#   * the quote's report data is those 64 bytes, and both attributes are the
#     base64 of the CSR and of the quote configfs-tsm returned
#   * the CSR is reused byte for byte while the names and key are unchanged, and
#     rebuilt when apps-domain or the key changes
#   * a publish the metadata server refuses fails without a marker (so the
#     watcher retries), and calimero-init never lets it stop the boot
#   * install: a chain for this key is written 0644 and traefik restarted; a
#     chain for another key, garbage, a broken chain or the same chain again
#     leave cert.pem alone and traefik running
#   * poll-once: 404 while tls-cert is unset, installs on a new ETag, nothing on
#     the same one
#   * the role installs the tool and its unit, and calimero-init publishes after
#     the TLS key exists and starts the unit with traefik
#
# Usage: scripts/ci/tests/tls-csr-test.sh
# shellcheck disable=SC2016
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ROLE="${REPO_ROOT}/mero-tee/ansible/roles/merotee"
TOOL="${ROLE}/files/calimero-tls-cert.sh"
TEMPLATE="${ROLE}/templates/calimero-init.sh.j2"
TASKS="${ROLE}/tasks/main.yml"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok: $*"; }
[[ -x "$TOOL" ]] || fail "${TOOL} is missing or not executable"

WORK="$(mktemp -d)"
SERVER_PID=""
cleanup() {
  [[ -z "$SERVER_PID" ]] || kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- the mock GCE metadata server --------------------------------------------
# GET  .../instance/attributes/<key>   from $META/attrs/<key>; 404 when absent;
#      ETag = sha256 of the value; wait_for_change with the current ETag as
#      last_etag waits (at most timeout_sec, capped at 2s) and then returns it.
# PUT  .../instance/guest-attributes/calimero/<key>  into $META/guest/<key>;
#      403 while $META/deny-guest exists (guest attributes not enabled).
# Anything without Metadata-Flavor: Google is refused, as GCE does.
META="$WORK/meta"
mkdir -p "$META/attrs" "$META/guest"
cat >"$WORK/server.py" <<'PY'
import hashlib, os, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

root = sys.argv[1]
ATTRS = "/computeMetadata/v1/instance/attributes/"
GUEST = "/computeMetadata/v1/instance/guest-attributes/calimero/"

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
        if not url.path.startswith(ATTRS):
            return self.reply(404)
        path = os.path.join(root, "attrs", url.path[len(ATTRS):])
        q = parse_qs(url.query)
        with open(os.path.join(root, "requests"), "a") as f:
            f.write(self.path + "\n")
        def read():
            try:
                with open(path, "rb") as f:
                    body = f.read()
            except FileNotFoundError:
                return None, None
            return body, hashlib.sha256(body).hexdigest()[:16]
        body, etag = read()
        if body is None:
            return self.reply(404)
        if q.get("wait_for_change") == ["true"] and q.get("last_etag", [""])[0] == etag:
            deadline = time.time() + min(2.0, float(q.get("timeout_sec", ["2"])[0]))
            while time.time() < deadline:
                time.sleep(0.1)
                body, now = read()
                if body is None:
                    return self.reply(404)
                if now != etag:
                    etag = now
                    break
        self.reply(200, body, etag)

    def do_PUT(self):
        if self.headers.get("Metadata-Flavor") != "Google":
            return self.reply(403)
        url = urlsplit(self.path)
        if not url.path.startswith(GUEST) or os.path.exists(os.path.join(root, "deny-guest")):
            return self.reply(403)
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        with open(os.path.join(root, "guest", url.path[len(GUEST):]), "wb") as f:
            f.write(body)
        self.reply(200)

srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
with open(os.path.join(root, "port"), "w") as f:
    f.write(str(srv.server_address[1]))
srv.serve_forever()
PY
python3 "$WORK/server.py" "$META" &
SERVER_PID=$!
for _ in $(seq 50); do [[ -s "$META/port" ]] && break; sleep 0.1; done
[[ -s "$META/port" ]] || fail "the mock metadata server did not start"
export no_proxy="127.0.0.1,localhost" NO_PROXY="127.0.0.1,localhost"

# --- the node, outside a TD -------------------------------------------------------
PORT="$(cat "$META/port")"
export CALIMERO_METADATA_ROOT="http://127.0.0.1:${PORT}/computeMetadata/v1/instance"
export CALIMERO_TLS_DIR="$WORK/tls"
export CALIMERO_TSM_REPORT="$WORK/tsm/report/calimero-tls-csr"
export CALIMERO_TLS_STATE_DIR="$WORK/run"
export CALIMERO_TLS_POLL_TIMEOUT=1
mkdir -p "$CALIMERO_TLS_DIR" "$CALIMERO_TSM_REPORT" "$WORK/bin"
# configfs-tsm: whatever is in outblob is "the quote" (the test checks inblob).
printf 'QUOTE-%s' "$RANDOM" >"$CALIMERO_TSM_REPORT/outblob"
cat >"$WORK/bin/systemctl" <<STUB
#!/usr/bin/env bash
echo "\$*" >>"$WORK/systemctl.log"
STUB
chmod +x "$WORK/bin/systemctl"
export PATH="$WORK/bin:$PATH"

KEY="$CALIMERO_TLS_DIR/key.pem"
CSR="$CALIMERO_TLS_DIR/csr.der"
CERT="$CALIMERO_TLS_DIR/cert.pem"
# What calimero-init makes: an EC P-256 key and a self-signed placeholder.
new_node_key() {
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$KEY" -out "$CERT" -days 3650 -subj "/CN=calimero-fleet-node" 2>/dev/null
  chmod 0644 "$CERT"
}
new_node_key

set_meta() { printf '%s' "$2" >"$META/attrs/$1"; }
unset_meta() { rm -f "$META/attrs/$1"; }
tool() { "$TOOL" "$@" 2>>"$WORK/tool.log"; }

csr_sans() {
  openssl req -inform DER -in "$1" -noout -text \
    | awk '/X509v3 Subject Alternative Name/{getline; gsub(/^[ \t]+|[ \t]+$/, ""); print; exit}'
}

# --- names ----------------------------------------------------------------------
set_meta public-url "https://Node-1.EU1.Example.com:443/some/path"
unset_meta apps-domain
[[ "$(tool names)" == "node-1.eu1.example.com" ]] || fail "names without apps-domain: $(tool names)"
set_meta apps-domain "Apps.Example.COM."
[[ "$(tool names)" == $'node-1.eu1.example.com\n*.apps.example.com' ]] \
  || fail "names with apps-domain: $(tool names)"
set_meta public-url "https://user@n2.example.com/"
unset_meta apps-domain
[[ "$(tool names)" == "n2.example.com" ]] || fail "userinfo is not part of the host: $(tool names)"
for bad in "http://n1.example.com/" "https://10.0.0.1/" "https://[2001:db8::1]:443/" "https://localhost/" ""; do
  set_meta public-url "$bad"
  if tool names >/dev/null; then fail "names accepted public-url '$bad'"; fi
  if tool publish; then fail "published a CSR for public-url '$bad'"; fi
done
[[ ! -e "$CSR" && -z "$(ls -A "$META/guest")" ]] || fail "something was published for an unusable public-url"
set_meta public-url "https://n1.example.com/"
set_meta apps-domain "bad_domain.example.com"
if tool publish; then fail "published a CSR for an apps-domain that is not a DNS name"; fi
pass "names: the public-url host and *.<apps-domain>, lowercased; nothing for a non-DNS or non-https name"

# --- publish: the CSR, its names and the quote's report data ------------------------
set_meta public-url "https://N1.Example.com:8443/"
unset_meta apps-domain
tool publish || fail "publish failed: $(tail -5 "$WORK/tool.log")"
[[ -s "$CSR" ]] || fail "no CSR at $CSR"
openssl req -inform DER -in "$CSR" -noout -verify >/dev/null 2>&1 || fail "the CSR's self-signature does not verify"
[[ "$(openssl req -inform DER -in "$CSR" -noout -subject -nameopt RFC2253)" == "subject=CN=n1.example.com" ]] \
  || fail "the CSR's subject is not CN=<host>"
[[ "$(csr_sans "$CSR")" == "DNS:n1.example.com" ]] || fail "SANs without apps-domain: $(csr_sans "$CSR")"
csr_key="$(openssl req -inform DER -in "$CSR" -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum)"
node_key="$(openssl pkey -in "$KEY" -pubout -outform DER | sha256sum)"
[[ "$csr_key" == "$node_key" ]] || fail "the CSR is not over key.pem"

# The report data, computed independently of the tool.
python3 - "$CSR" "$CALIMERO_TSM_REPORT/inblob" <<'PY' || fail "the quote's report data is not SHA-256(CSR) || SHA-256(domain)"
import hashlib, sys
csr = open(sys.argv[1], "rb").read()
inblob = open(sys.argv[2], "rb").read()
want = hashlib.sha256(csr).digest() + hashlib.sha256(b"calimero.tee-attest.tls-csr.v1").digest()
assert len(inblob) == 64, len(inblob)
assert inblob == want, (inblob.hex(), want.hex())
# mdma's CSR_BINDING, as hex, is the second half.
assert inblob[32:].hex() == hashlib.sha256(b"calimero.tee-attest.tls-csr.v1").hexdigest()
PY
cmp -s <(tool report-data "$CSR") "$CALIMERO_TSM_REPORT/inblob" || fail "report-data differs from what was quoted"
[[ "$(cat "$META/guest/tls-csr")" == "$(base64 -w0 <"$CSR")" ]] || fail "guest attribute tls-csr is not base64 of csr.der"
[[ "$(cat "$META/guest/tls-quote")" == "$(base64 -w0 <"$CALIMERO_TSM_REPORT/outblob")" ]] \
  || fail "guest attribute tls-quote is not base64 of the configfs-tsm quote"
[[ "$(wc -l <"$META/guest/tls-csr")" == 0 ]] || fail "tls-csr is wrapped or has a newline"
[[ -e "$CALIMERO_TLS_STATE_DIR/tls-csr-published" ]] || fail "no published marker after a publish"
pass "publish: CSR for exactly the host, report data SHA-256(CSR) || SHA-256(domain), both attributes base64"

# --- the CSR is stable, and follows the names and the key ---------------------------
before="$(sha256sum <"$CSR")"
tool publish || fail "second publish failed"
[[ "$(sha256sum <"$CSR")" == "$before" ]] || fail "the CSR was rebuilt though its names and key are unchanged"
pass "CSR reused byte for byte while names and key are unchanged"

set_meta apps-domain "apps.example.com"
tool publish || fail "publish with apps-domain failed"
[[ "$(sha256sum <"$CSR")" != "$before" ]] || fail "the CSR was not rebuilt when apps-domain was set"
[[ "$(csr_sans "$CSR")" == "DNS:n1.example.com, DNS:*.apps.example.com" ]] \
  || fail "SANs with apps-domain: $(csr_sans "$CSR")"
openssl req -inform DER -in "$CSR" -noout -text | grep -q 'IP Address' && fail "the CSR names an IP address"
cmp -s <(tool report-data "$CSR") "$CALIMERO_TSM_REPORT/inblob" || fail "the new CSR was not the one quoted"
[[ "$(cat "$META/guest/tls-csr")" == "$(base64 -w0 <"$CSR")" ]] || fail "tls-csr not republished for the new CSR"
with_apps="$(sha256sum <"$CSR")"
tool publish || fail "publish failed"
[[ "$(sha256sum <"$CSR")" == "$with_apps" ]] || fail "the CSR with apps-domain was not reused"
pass "CSR rebuilt when apps-domain changes, then reused"

cp "$KEY" "$WORK/key.orig"
openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl pkey -out "$KEY"
tool publish || fail "publish with a new key failed"
[[ "$(openssl req -inform DER -in "$CSR" -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum)" \
    == "$(openssl pkey -in "$KEY" -pubout -outform DER | sha256sum)" ]] || fail "the CSR was not rebuilt for a new key"
cp "$WORK/key.orig" "$KEY"
tool publish || fail "publish failed"
pass "CSR rebuilt when the key changes"

# --- publish failures ---------------------------------------------------------------
rm -f "$CALIMERO_TLS_STATE_DIR/tls-csr-published"
touch "$META/deny-guest"
if tool publish; then fail "publish succeeded though the metadata server refused the guest attributes"; fi
[[ ! -e "$CALIMERO_TLS_STATE_DIR/tls-csr-published" ]] || fail "a failed publish left the published marker"
rm -f "$META/deny-guest"
mv "$CALIMERO_TSM_REPORT/outblob" "$WORK/outblob"
if CALIMERO_TSM_REPORT="$WORK/tsm/report/missing/nested" tool publish; then
  fail "publish succeeded without a quote"
fi
mv "$WORK/outblob" "$CALIMERO_TSM_REPORT/outblob"
tool publish || fail "publish failed"
pass "a refused write or a missing quote fails the publish and leaves no marker"

# --- install ---------------------------------------------------------------------
# A CA and an intermediate, as an ACME chain looks: leaf, then intermediate.
ca() {
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/root.key" \
    -out "$WORK/root.pem" -days 30 -subj "/CN=Test Root" -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign" 2>/dev/null
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/int.key" \
    -subj "/CN=Test Intermediate" -out "$WORK/int.csr" 2>/dev/null
  printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n' >"$WORK/int.ext"
  openssl x509 -req -in "$WORK/int.csr" -CA "$WORK/root.pem" -CAkey "$WORK/root.key" -CAcreateserial \
    -days 30 -extfile "$WORK/int.ext" -out "$WORK/int.pem" 2>/dev/null
}
# leaf_for CSR_DER OUT [DAYS]: what the CA issues for a CSR.
leaf_for() {
  printf 'subjectAltName=DNS:n1.example.com\n' >"$WORK/leaf.ext"
  openssl x509 -req -inform DER -in "$1" -CA "$WORK/int.pem" -CAkey "$WORK/int.key" -CAcreateserial \
    -days "${3:-30}" -extfile "$WORK/leaf.ext" -out "$2" 2>/dev/null
}
ca
leaf_for "$CSR" "$WORK/leaf.pem"
cat "$WORK/leaf.pem" "$WORK/int.pem" >"$WORK/chain.pem"

placeholder="$(sha256sum <"$CERT")"
refused() {
  local what="$1" file="$2"
  : >"$WORK/systemctl.log"
  if tool install "$file"; then fail "installed $what"; fi
  [[ "$(sha256sum <"$CERT")" == "$placeholder" ]] || fail "cert.pem changed after refusing $what"
  [[ ! -s "$WORK/systemctl.log" ]] || fail "traefik restarted after refusing $what"
}

# A chain for another key, from the same CA: what a host writing metadata could do.
openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl pkey -out "$WORK/other.key"
openssl req -new -config /dev/null -key "$WORK/other.key" -subj "/CN=n1.example.com" \
  -addext "subjectAltName=DNS:n1.example.com" -outform DER -out "$WORK/other.csr"
leaf_for "$WORK/other.csr" "$WORK/other-leaf.pem"
cat "$WORK/other-leaf.pem" "$WORK/int.pem" >"$WORK/other-chain.pem"
refused "a chain for another key" "$WORK/other-chain.pem"
grep -q "not for this node's key" "$WORK/tool.log" || fail "the refusal does not say the key differs"
printf 'not a certificate\n' >"$WORK/garbage.pem"
refused "text with no certificate" "$WORK/garbage.pem"
sed '2s/^.\{8\}/AAAAAAAA/' "$WORK/leaf.pem" >"$WORK/corrupt.pem"
cat "$WORK/corrupt.pem" "$WORK/int.pem" >"$WORK/corrupt-chain.pem"
refused "a chain whose leaf does not parse" "$WORK/corrupt-chain.pem"
cat "$WORK/leaf.pem" "$WORK/root.pem" >"$WORK/skip-chain.pem"
refused "a chain whose leaf is not signed by the next certificate" "$WORK/skip-chain.pem"
: >"$WORK/empty.pem"
refused "an empty value" "$WORK/empty.pem"
pass "install refuses another key's chain, garbage, a broken chain and an empty value; placeholder kept"

: >"$WORK/systemctl.log"
{ echo "leading text"; cat "$WORK/chain.pem"; } >"$WORK/chain-with-text.pem"
tool install "$WORK/chain-with-text.pem" || fail "the chain for this key was not installed: $(tail -3 "$WORK/tool.log")"
[[ "$(stat -c %a "$CERT")" == 644 ]] || fail "cert.pem is $(stat -c %a "$CERT"), not 0644"
[[ "$(grep -c 'BEGIN CERTIFICATE' "$CERT")" == 2 ]] || fail "cert.pem does not hold the leaf and the intermediate"
grep -q "leading text" "$CERT" && fail "cert.pem kept text outside the certificates"
cmp -s <(openssl x509 -in "$CERT" -outform DER) <(openssl x509 -in "$WORK/leaf.pem" -outform DER) \
  || fail "cert.pem does not start with the leaf"
[[ "$(cat "$WORK/systemctl.log")" == "restart traefik" ]] || fail "traefik not restarted: $(cat "$WORK/systemctl.log")"
compgen -G "$CALIMERO_TLS_DIR/.cert.*" >/dev/null && fail "a temporary file was left in $CALIMERO_TLS_DIR"
: >"$WORK/systemctl.log"
tool install "$WORK/chain.pem" || fail "reinstalling the same chain failed"
[[ ! -s "$WORK/systemctl.log" ]] || fail "traefik restarted for the chain it already serves"
installed="$(sha256sum <"$CERT")"
placeholder="$installed"
refused "another key's chain over an issued one" "$WORK/other-chain.pem"
pass "install writes this key's chain 0644, leaf first, and restarts traefik once"

# --- poll-once against tls-cert metadata --------------------------------------------
unset_meta tls-cert
rc=0; tool poll-once >/dev/null || rc=$?
[[ "$rc" == 2 ]] || fail "poll-once with tls-cert unset exited $rc, not 2"

# A new chain (a renewal) arrives under a new ETag.
leaf_for "$CSR" "$WORK/leaf2.pem"
cat "$WORK/leaf2.pem" "$WORK/int.pem" >"$WORK/chain2.pem"
set_meta tls-cert "$(cat "$WORK/chain2.pem")"
: >"$WORK/systemctl.log"
etag="$(tool poll-once)" || fail "poll-once failed"
[[ -n "$etag" && "$etag" != NONE ]] || fail "poll-once printed no ETag"
cmp -s <(openssl x509 -in "$CERT" -outform DER) <(openssl x509 -in "$WORK/leaf2.pem" -outform DER) \
  || fail "the renewed chain was not installed"
[[ "$(cat "$WORK/systemctl.log")" == "restart traefik" ]] || fail "traefik not restarted on renewal"
grep -q 'wait_for_change=true&last_etag=NONE' "$META/requests" || fail "the first poll does not pass last_etag"

: >"$WORK/systemctl.log"
[[ "$(tool poll-once "$etag")" == "$etag" ]] || fail "the ETag changed with no change"
[[ ! -s "$WORK/systemctl.log" ]] || fail "traefik restarted though tls-cert did not change"
grep -q "last_etag=${etag}" "$META/requests" || fail "poll-once did not pass the ETag it was given"

set_meta tls-cert "$(cat "$WORK/other-chain.pem")"
before="$(sha256sum <"$CERT")"
tool poll-once "$etag" >/dev/null || fail "poll-once failed on a refused chain"
[[ "$(sha256sum <"$CERT")" == "$before" ]] || fail "poll-once installed another key's chain"
pass "poll-once: 404 while unset, installs on a new ETag, nothing on the same one or another key"

# --- watch: retries the boot's publish, then installs what arrives ---------------------
rm -f "$CALIMERO_TLS_STATE_DIR/tls-csr-published" "$META/guest/tls-csr"
leaf_for "$CSR" "$WORK/leaf3.pem"
cat "$WORK/leaf3.pem" "$WORK/int.pem" >"$WORK/chain3.pem"
set_meta tls-cert "$(cat "$WORK/chain3.pem")"
: >"$WORK/systemctl.log"
rc=0
CALIMERO_TLS_BACKOFF_MIN=1 timeout 4 "$TOOL" watch 2>>"$WORK/tool.log" || rc=$?
[[ "$rc" == 124 ]] || fail "watch exited ($rc) instead of running until stopped"
[[ -e "$CALIMERO_TLS_STATE_DIR/tls-csr-published" && -s "$META/guest/tls-csr" ]] \
  || fail "watch did not publish the CSR the boot had not"
cmp -s <(openssl x509 -in "$CERT" -outform DER) <(openssl x509 -in "$WORK/leaf3.pem" -outform DER) \
  || fail "watch did not install the chain in tls-cert"
[[ "$(cat "$WORK/systemctl.log")" == "restart traefik" ]] || fail "watch restarted traefik other than once"
pass "watch publishes when the boot did not, installs tls-cert once, and keeps running"

# --- the image wiring ------------------------------------------------------------------
grep -qF 'src: calimero-tls-cert.sh' "$TASKS" || fail "the role does not install calimero-tls-cert.sh"
grep -qF 'dest: /usr/local/lib/calimero/tls-cert.sh' "$TASKS" || fail "the tool is not at /usr/local/lib/calimero/tls-cert.sh"
grep -qF 'ExecStart=/usr/local/lib/calimero/tls-cert.sh watch' "$TASKS" || fail "no unit runs the watcher"
grep -qF 'dest: /etc/systemd/system/calimero-tls-cert.service' "$TASKS" || fail "no calimero-tls-cert.service"
grep -qF 'TLS_CERT_TOOL="/usr/local/lib/calimero/tls-cert.sh"' "$TEMPLATE" || fail "calimero-init does not name the tool"
key_line="$(grep -n 'TLS_DIR="/mnt/data/tls"' "$TEMPLATE" | head -1 | cut -d: -f1)"
publish_line="$(grep -n '"$TLS_CERT_TOOL" publish' "$TEMPLATE" | head -1 | cut -d: -f1)"
services_line="$(grep -n '^log "Starting services..."' "$TEMPLATE" | head -1 | cut -d: -f1)"
if ! [[ -n "$key_line" && -n "$publish_line" && -n "$services_line" ]] \
    || ! (( key_line < publish_line && publish_line < services_line )); then
  fail "calimero-init must publish after the TLS key exists and before services start"
fi
grep -qE '^  if timeout [0-9]+ "\$TLS_CERT_TOOL" publish .*; then$' "$TEMPLATE" \
  || fail "calimero-init's publish must be a bounded if-condition, so a failure cannot stop the boot"
[[ "$(grep -c 'systemctl enable .*traefik calimero-tls-cert' "$TEMPLATE")" == 2 ]] \
  || fail "calimero-init must enable calimero-tls-cert with traefik on both paths"
[[ "$(grep -c 'systemctl start --no-block .*traefik calimero-tls-cert' "$TEMPLATE")" == 2 ]] \
  || fail "calimero-init must start calimero-tls-cert with traefik on both paths"
pass "the role installs the tool and unit; calimero-init publishes before services and starts the unit"

echo "PASS: tls-csr-test"
