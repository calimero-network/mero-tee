#!/usr/bin/env bash
# Custom domains: the node asks mdma for one certificate per served host, for
# its attested TLS key, and Traefik serves only chains for that key and host.
#
# mdma writes instance metadata `tls-custom-hosts` (a JSON array of hosts) and,
# once issued, `tls-cert-custom` ({"<host>": "<PEM chain>"}); it reads guest
# attributes calimero/tls-csr-custom ({"<host>": "<base64 DER CSR>"}) and
# calimero/tls-custom-installed (a JSON array) -- core
# docs/specs/custom-domains.md, sections 7-10. The host can write that metadata
# too. This runs mero-tee/ansible/roles/merotee/files/calimero-tls-cert.sh, the
# tool the image installs, against a mock metadata server (with the recursive
# attributes listing `watch-custom` long-polls) and a stub systemctl, and
# checks:
#
#   * one CSR per listed host over key.pem, naming exactly CN=<host> and
#     DNS:<host>, published as calimero/tls-csr-custom; reused byte for byte,
#     rebuilt for a new key, dropped with its host; `{}` for no hosts
#   * tls-custom-hosts is lowercased and sorted; entries that are not DNS names
#     are left out; a value that is not a JSON array, or one with too many
#     hosts, changes nothing
#   * a chain is installed at custom/<host>.pem only for this key, signed
#     through, unexpired and naming exactly its host; one for another key, for
#     another host, with a second name, for an unlisted host or under a
#     traversal key is refused, and a bad renewal keeps the installed chain
#   * Traefik's dynamic file lists each installed chain with key.pem, parses as
#     YAML, changes on a renewal (so the watched directory reloads), and drops a
#     removed host; traefik is never restarted, cert.pem and calimero/tls-csr
#     never touched
#   * calimero/tls-custom-installed names exactly the installed hosts
#   * poll-custom-once and watch-custom read both keys from the attributes
#     listing and reconcile; a refused guest-attribute write is retried
#   * the image wiring: the static config's watched directory, routing.yml in
#     it, the unit, calimero-init starting it with traefik, vector collecting it
#
# Usage: scripts/ci/tests/tls-custom-test.sh
# shellcheck disable=SC2016
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ROLE="${REPO_ROOT}/mero-tee/ansible/roles/merotee"
TRAEFIK_ROLE="${REPO_ROOT}/mero-tee/ansible/roles/mero-traefik"
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
# GET  .../instance/attributes/?recursive=true  every key in $META/attrs as a
#      JSON object; ETag = sha256 of that listing; wait_for_change with the
#      current ETag waits (at most timeout_sec, capped at 2s).
# GET  .../instance/attributes/<key>  one value; 404 when absent.
# PUT  .../instance/guest-attributes/calimero/<key>  into $META/guest/<key>;
#      403 while $META/deny-guest exists.
META="$WORK/meta"
mkdir -p "$META/attrs" "$META/guest"
cat >"$WORK/server.py" <<'PY'
import hashlib, json, os, sys, time
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
        key = url.path[len(ATTRS):]
        q = parse_qs(url.query)
        with open(os.path.join(root, "requests"), "a") as f:
            f.write(self.path + "\n")
        def read():
            d = os.path.join(root, "attrs")
            if key == "":
                if q.get("recursive") != ["true"]:
                    return None, None
                listing = {}
                for name in sorted(os.listdir(d)):
                    with open(os.path.join(d, name), encoding="utf-8") as f:
                        listing[name] = f.read()
                body = json.dumps(listing).encode()
            else:
                try:
                    with open(os.path.join(d, key), "rb") as f:
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
        with open(os.path.join(root, "puts"), "a") as f:
            f.write(url.path[len(GUEST):] + "\n")
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

# --- the node, outside a TD ---------------------------------------------------
PORT="$(cat "$META/port")"
export CALIMERO_METADATA_ROOT="http://127.0.0.1:${PORT}/computeMetadata/v1/instance"
export CALIMERO_TLS_DIR="$WORK/tls"
export CALIMERO_TLS_STATE_DIR="$WORK/run"
export CALIMERO_TRAEFIK_DYNAMIC_DIR="$WORK/traefik/dynamic"
export CALIMERO_TLS_POLL_TIMEOUT=1
export CALIMERO_TLS_MAX_CUSTOM_HOSTS=4
mkdir -p "$CALIMERO_TLS_DIR" "$WORK/bin"
cat >"$WORK/bin/systemctl" <<STUB
#!/usr/bin/env bash
echo "\$*" >>"$WORK/systemctl.log"
STUB
chmod +x "$WORK/bin/systemctl"
export PATH="$WORK/bin:$PATH"
: >"$WORK/systemctl.log"

KEY="$CALIMERO_TLS_DIR/key.pem"
CERT="$CALIMERO_TLS_DIR/cert.pem"
CUSTOM="$CALIMERO_TLS_DIR/custom"
CSRS="$CALIMERO_TLS_DIR/custom-csr"
DYN="$CALIMERO_TRAEFIK_DYNAMIC_DIR/custom-certs.yml"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$KEY" -out "$CERT" -days 3650 -subj "/CN=calimero-fleet-node" 2>/dev/null
# The node certificate's own CSR attribute, which nothing here may touch.
printf 'NODE-CSR' >"$META/guest/tls-csr"
node_cert="$(sha256sum <"$CERT")"

tool() { "$TOOL" "$@" 2>>"$WORK/tool.log"; }
reconcile() { tool reconcile-custom "$@"; }
spki() { openssl pkey -pubin -outform DER | sha256sum; }
key_spki() { openssl pkey -in "$KEY" -pubout | spki; }
guest_json() { python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])), sort_keys=True))' "$META/guest/$1"; }
installed() { python3 -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))))' "$META/guest/tls-custom-installed"; }

# --- tls-custom-hosts parsing ----------------------------------------------------
[[ "$(tool custom-hosts '["B.Example.org.","kv.example.com","kv.example.com"]')" == $'b.example.org\nkv.example.com' ]] \
  || fail "hosts are not lowercased, deduplicated and sorted: $(tool custom-hosts '["B.Example.org.","kv.example.com"]')"
[[ "$(tool custom-hosts '["*.example.com","10.0.0.1","../etc","a b.com","x.example.com",""]')" == "x.example.com" ]] \
  || fail "non-DNS entries were not left out"
[[ -z "$(tool custom-hosts '')" ]] || fail "an unset value is not the empty set"
[[ -z "$(tool custom-hosts '[]')" ]] || fail "[] is not the empty set"
for bad in '{"kv.example.com":1}' 'kv.example.com' '[1]' '["a.com","b.com","c.com","d.com","e.com"]'; do
  if tool custom-hosts "$bad" >/dev/null; then fail "custom-hosts accepted '$bad'"; fi
done
pass "tls-custom-hosts: lowercased, sorted, non-DNS entries left out, a bad value or too many hosts refused"

# --- CSRs -------------------------------------------------------------------------
reconcile '' '' || fail "reconcile with nothing listed failed: $(tail -3 "$WORK/tool.log")"
[[ "$(guest_json tls-csr-custom)" == "{}" ]] || fail "no hosts did not publish {}"
[[ "$(guest_json tls-custom-installed)" == "[]" ]] || fail "no hosts did not report []"
python3 -c 'import sys,yaml; d=yaml.safe_load(open(sys.argv[1])); assert d == {"tls": {"certificates": []}}, d' "$DYN" \
  || fail "the empty dynamic file is not tls.certificates: []"

HOSTS='["kv.example.com","shop.example.org"]'
reconcile "$HOSTS" '' || fail "reconcile with two hosts failed: $(tail -3 "$WORK/tool.log")"
python3 - "$META/guest/tls-csr-custom" "$CSRS" <<'PY' || fail "tls-csr-custom is not {host: base64 of custom-csr/<host>.der}"
import base64, json, sys
d = json.load(open(sys.argv[1]))
assert sorted(d) == ["kv.example.com", "shop.example.org"], sorted(d)
for host, b64 in d.items():
    assert base64.b64decode(b64) == open(f"{sys.argv[2]}/{host}.der", "rb").read(), host
PY
for h in kv.example.com shop.example.org; do
  csr="$CSRS/$h.der"
  openssl req -inform DER -in "$csr" -noout -verify >/dev/null 2>&1 || fail "the CSR for $h does not verify"
  [[ "$(openssl req -inform DER -in "$csr" -noout -subject -nameopt RFC2253)" == "subject=CN=$h" ]] \
    || fail "the CSR for $h is not CN=$h"
  [[ "$(openssl req -inform DER -in "$csr" -noout -text | awk '/Subject Alternative Name/{getline; gsub(/^[ \t]+|[ \t]+$/, ""); print}')" == "DNS:$h" ]] \
    || fail "the CSR for $h does not name exactly DNS:$h"
  [[ "$(openssl req -inform DER -in "$csr" -noout -pubkey | spki)" == "$(key_spki)" ]] || fail "the CSR for $h is not over key.pem"
done
[[ "$(cat "$META/guest/tls-csr")" == NODE-CSR ]] || fail "the node's calimero/tls-csr was touched"
csr_kv="$(sha256sum <"$CSRS/kv.example.com.der")"
: >"$META/puts"
reconcile "$HOSTS" '' || fail "second reconcile failed"
[[ "$(sha256sum <"$CSRS/kv.example.com.der")" == "$csr_kv" ]] || fail "the CSR was rebuilt with nothing changed"
[[ ! -s "$META/puts" ]] || fail "unchanged values were written again: $(cat "$META/puts")"
pass "one CSR per host over key.pem, exactly CN/DNS of the host, published as tls-csr-custom and reused"

# --- certificates ------------------------------------------------------------------
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/root.key" \
  -out "$WORK/root.pem" -days 30 -subj "/CN=Test Root" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign" 2>/dev/null
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/int.key" \
  -subj "/CN=Test Intermediate" -out "$WORK/int.csr" 2>/dev/null
printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n' >"$WORK/int.ext"
openssl x509 -req -in "$WORK/int.csr" -CA "$WORK/root.pem" -CAkey "$WORK/root.key" -CAcreateserial \
  -days 30 -extfile "$WORK/int.ext" -out "$WORK/int.pem" 2>/dev/null
# chain_for CSR_DER SAN OUT [DAYS]: what the CA issues, leaf then intermediate.
chain_for() {
  printf 'subjectAltName=%s\n' "$2" >"$WORK/leaf.ext"
  openssl x509 -req -inform DER -in "$1" -CA "$WORK/int.pem" -CAkey "$WORK/int.key" -CAcreateserial \
    -days "${4:-30}" -extfile "$WORK/leaf.ext" -out "$WORK/leaf.tmp" 2>/dev/null
  cat "$WORK/leaf.tmp" "$WORK/int.pem" >"$3"
}
# certs_json HOST=FILE...: a tls-cert-custom value.
certs_json() {
  python3 -c '
import json, sys
print(json.dumps({k: open(p).read() for k, _, p in (a.partition("=") for a in sys.argv[1:])}))' "$@"
}
chain_for "$CSRS/kv.example.com.der" "DNS:kv.example.com" "$WORK/kv.pem"
chain_for "$CSRS/shop.example.org.der" "DNS:shop.example.org" "$WORK/shop.pem"

reconcile "$HOSTS" "$(certs_json kv.example.com="$WORK/kv.pem")" || fail "installing kv failed: $(tail -3 "$WORK/tool.log")"
[[ -s "$CUSTOM/kv.example.com.pem" ]] || fail "no chain at custom/kv.example.com.pem"
[[ "$(stat -c %a "$CUSTOM/kv.example.com.pem")" == 644 ]] || fail "the chain is not 0644"
[[ "$(grep -c 'BEGIN CERTIFICATE' "$CUSTOM/kv.example.com.pem")" == 2 ]] || fail "the chain is not leaf + intermediate"
[[ "$(installed)" == "kv.example.com" ]] || fail "tls-custom-installed is '$(installed)', not kv.example.com"
python3 - "$DYN" "$CUSTOM" "$KEY" <<'PY' || fail "the dynamic file does not list kv's chain with key.pem"
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
certs = d["tls"]["certificates"]
assert len(certs) == 1, certs
assert certs[0]["keyFile"] == sys.argv[3], certs[0]
assert certs[0]["certFile"] == open(sys.argv[2] + "/kv.example.com.pem").read(), "certFile is not the chain"
assert set(d) == {"tls"} and set(d["tls"]) == {"certificates"}, d
PY
reconcile "$HOSTS" "$(certs_json kv.example.com="$WORK/kv.pem" shop.example.org="$WORK/shop.pem")" \
  || fail "installing both failed"
[[ "$(installed)" == "kv.example.com shop.example.org" ]] || fail "tls-custom-installed: $(installed)"
python3 -c 'import sys,yaml; assert len(yaml.safe_load(open(sys.argv[1]))["tls"]["certificates"]) == 2' "$DYN" \
  || fail "the dynamic file does not list both"
pass "a chain for this key and its host is installed 0644, listed for Traefik with key.pem, reported installed"

# Refusals: each is offered for shop.example.org over its installed chain.
installed_shop="$(sha256sum <"$CUSTOM/shop.example.org.pem")"
dyn_before="$(sha256sum <"$DYN")"
offer() {
  local what="$1" value="$2"
  : >"$WORK/tool.log"
  reconcile "$HOSTS" "$value" || fail "reconcile failed offering $what"
  [[ "$(sha256sum <"$CUSTOM/shop.example.org.pem")" == "$installed_shop" ]] || fail "installed $what"
  [[ "$(sha256sum <"$DYN")" == "$dyn_before" ]] || fail "the dynamic file changed for $what"
  [[ "$(installed)" == "kv.example.com shop.example.org" ]] || fail "installed list changed for $what"
}
openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl pkey -out "$WORK/other.key"
openssl req -new -config /dev/null -key "$WORK/other.key" -subj "/CN=shop.example.org" \
  -addext "subjectAltName=DNS:shop.example.org" -outform DER -out "$WORK/other.csr"
chain_for "$WORK/other.csr" "DNS:shop.example.org" "$WORK/other.pem"
offer "a chain for another key" "$(certs_json kv.example.com="$WORK/kv.pem" shop.example.org="$WORK/other.pem")"
grep -q "REFUSED the tls-cert-custom chain for shop.example.org: the leaf certificate is not for this node's key" "$WORK/tool.log" \
  || fail "the refusal does not name the key: $(cat "$WORK/tool.log")"
offer "kv's chain filed under shop" "$(certs_json kv.example.com="$WORK/kv.pem" shop.example.org="$WORK/kv.pem")"
grep -q "not exactly DNS:shop.example.org" "$WORK/tool.log" || fail "the refusal does not name the host"
chain_for "$CSRS/shop.example.org.der" "DNS:shop.example.org,DNS:kv.example.com" "$WORK/two.pem"
offer "a chain naming a second host" "$(certs_json kv.example.com="$WORK/kv.pem" shop.example.org="$WORK/two.pem")"
awk '/BEGIN/{n++} n==1' "$WORK/shop.pem" >"$WORK/leafonly.pem"
cat "$WORK/leafonly.pem" "$WORK/root.pem" >"$WORK/broken.pem"
offer "a broken chain" "$(certs_json kv.example.com="$WORK/kv.pem" shop.example.org="$WORK/broken.pem")"
printf 'garbage' >"$WORK/garbage.pem"
offer "garbage" "$(certs_json kv.example.com="$WORK/kv.pem" shop.example.org="$WORK/garbage.pem")"
offer "a value that is not a JSON object" '["nope"]'
offer "a value that does not parse" '{"kv.example.com": '
pass "another key's chain, another host's, a second name, a broken chain, garbage and a bad value are refused; the installed chain kept"

# An unlisted host, and a traversal key: nothing is written for either.
reconcile "$HOSTS" "$(certs_json kv.example.com="$WORK/kv.pem" shop.example.org="$WORK/shop.pem" \
  evil.example.net="$WORK/kv.pem" ../../escape="$WORK/kv.pem")" || fail "reconcile failed"
[[ "$(cd "$CUSTOM" && ls)" == $'kv.example.com.pem\nshop.example.org.pem' ]] \
  || fail "custom/ holds more than the listed hosts' chains: $(ls -A "$CUSTOM")"
[[ ! -e "$CUSTOM/evil.example.net.pem" && ! -e "$WORK/escape.pem" && ! -e "$CALIMERO_TLS_DIR/escape.pem" ]] \
  || fail "an unlisted or traversal key was written"
pass "entries for hosts not in tls-custom-hosts are ignored"

# Renewal: a new chain replaces the old and changes the dynamic file.
chain_for "$CSRS/kv.example.com.der" "DNS:kv.example.com" "$WORK/kv2.pem"
reconcile "$HOSTS" "$(certs_json kv.example.com="$WORK/kv2.pem" shop.example.org="$WORK/shop.pem")" || fail "renewal failed"
cmp -s <(openssl x509 -in "$CUSTOM/kv.example.com.pem" -outform DER) <(openssl x509 -in "$WORK/kv2.pem" -outform DER) \
  || fail "the renewed chain was not installed"
[[ "$(sha256sum <"$DYN")" != "$dyn_before" ]] || fail "the dynamic file did not change on renewal; Traefik would keep the old chain"
pass "a renewal replaces the chain and rewrites the dynamic file"

# A listed host whose entry leaves tls-cert-custom keeps its chain while it is valid.
reconcile "$HOSTS" "$(certs_json kv.example.com="$WORK/kv2.pem")" || fail "reconcile failed"
[[ -s "$CUSTOM/shop.example.org.pem" && "$(installed)" == "kv.example.com shop.example.org" ]] \
  || fail "a listed host lost its valid chain when its entry went missing"

# Removal: shop leaves tls-custom-hosts.
reconcile '["kv.example.com"]' "$(certs_json kv.example.com="$WORK/kv2.pem" shop.example.org="$WORK/shop.pem")" \
  || fail "removal failed"
[[ ! -e "$CUSTOM/shop.example.org.pem" ]] || fail "the removed host's chain is still installed"
[[ ! -e "$CSRS/shop.example.org.der" ]] || fail "the removed host's CSR is still kept"
[[ "$(guest_json tls-csr-custom | python3 -c 'import json,sys; print(sorted(json.load(sys.stdin)))')" == "['kv.example.com']" ]] \
  || fail "tls-csr-custom still names the removed host"
[[ "$(installed)" == "kv.example.com" ]] || fail "tls-custom-installed still names the removed host"
grep -q shop.example.org "$DYN" && fail "the dynamic file still names the removed host"
pass "a host leaving tls-custom-hosts loses its chain, CSR, Traefik entry and installed report"

# A bad tls-custom-hosts changes nothing (it is not an empty list).
reconcile 'not json' "$(certs_json kv.example.com="$WORK/kv2.pem")" && fail "a bad tls-custom-hosts was accepted"
[[ -s "$CUSTOM/kv.example.com.pem" && "$(installed)" == "kv.example.com" ]] || fail "a bad tls-custom-hosts removed certificates"

# A new key: the CSR is rebuilt, and the old key's chain is no longer served.
cp "$KEY" "$WORK/key.orig"
openssl ecparam -name prime256v1 -genkey -noout 2>/dev/null | openssl pkey -out "$KEY"
reconcile '["kv.example.com"]' "$(certs_json kv.example.com="$WORK/kv2.pem")" || fail "reconcile with a new key failed"
[[ "$(openssl req -inform DER -in "$CSRS/kv.example.com.der" -noout -pubkey | spki)" == "$(key_spki)" ]] \
  || fail "the CSR was not rebuilt for the new key"
[[ ! -e "$CUSTOM/kv.example.com.pem" && "$(installed)" == "" ]] || fail "a chain for the old key is still installed"
cp "$WORK/key.orig" "$KEY"
reconcile '["kv.example.com"]' "$(certs_json kv.example.com="$WORK/kv2.pem")" || fail "reconcile failed"
[[ "$(installed)" == "kv.example.com" ]] || fail "the chain was not reinstalled for the original key"
pass "a bad host list changes nothing; a new key rebuilds the CSR and drops the old key's chain"

# Expiry: a chain that expires is dropped on the next pass.
chain_for "$CSRS/kv.example.com.der" "DNS:kv.example.com" "$WORK/kv-short.pem" 0
sleep 1
reconcile '["kv.example.com"]' "$(certs_json kv.example.com="$WORK/kv-short.pem")" || fail "reconcile failed"
grep -q "REFUSED the tls-cert-custom chain for kv.example.com: the leaf certificate has expired" "$WORK/tool.log" \
  || fail "an expired chain was not refused"
[[ "$(installed)" == "kv.example.com" ]] || fail "the valid chain was dropped for an expired offer"
pass "an expired chain is refused"

[[ ! -s "$WORK/systemctl.log" ]] || fail "traefik was restarted: $(cat "$WORK/systemctl.log")"
[[ "$(sha256sum <"$CERT")" == "$node_cert" ]] || fail "cert.pem was touched"
[[ "$(cat "$META/guest/tls-csr")" == NODE-CSR ]] || fail "calimero/tls-csr was touched"
pass "no traefik restart; cert.pem and calimero/tls-csr untouched"

# --- poll-custom-once and watch-custom ---------------------------------------------------
rm -f "$META/guest/tls-csr-custom" "$META/guest/tls-custom-installed" "$CALIMERO_TLS_STATE_DIR"/tls-*.last
printf '%s' '["kv.example.com","shop.example.org"]' >"$META/attrs/tls-custom-hosts"
certs_json kv.example.com="$WORK/kv2.pem" shop.example.org="$WORK/shop.pem" | tr -d '\n' >"$META/attrs/tls-cert-custom"
printf 'unrelated' >"$META/attrs/public-url"
mkdir -p "$WORK/tmpdir"
etag="$(TMPDIR="$WORK/tmpdir" tool poll-custom-once)" || fail "poll-custom-once failed: $(tail -3 "$WORK/tool.log")"
[[ -n "$etag" && "$etag" != NONE ]] || fail "poll-custom-once printed no ETag"
grep -q 'attributes/?recursive=true&wait_for_change=true&last_etag=NONE' "$META/requests" \
  || fail "poll-custom-once does not long-poll the attributes listing"
[[ "$(installed)" == "kv.example.com shop.example.org" ]] || fail "poll-custom-once did not reconcile: $(installed)"
[[ -z "$(find "$WORK/tmpdir" -name custom-attrs)" ]] || fail "the attributes listing was left on disk"
: >"$META/puts"
[[ "$(tool poll-custom-once "$etag")" == "$etag" ]] || fail "the ETag changed with no change"
[[ ! -s "$META/puts" ]] || fail "an unchanged listing was published again"

# watch-custom: a removal arrives; a refused write is retried until it lands.
printf '%s' '["kv.example.com"]' >"$META/attrs/tls-custom-hosts"
touch "$META/deny-guest"
( sleep 2; rm -f "$META/deny-guest" ) &
rc=0
CALIMERO_TLS_BACKOFF_MIN=1 timeout 6 "$TOOL" watch-custom 2>>"$WORK/tool.log" || rc=$?
[[ "$rc" == 124 ]] || fail "watch-custom exited ($rc) instead of running until stopped"
[[ ! -e "$CUSTOM/shop.example.org.pem" ]] || fail "watch-custom did not remove shop's chain"
[[ "$(installed)" == "kv.example.com" ]] || fail "watch-custom did not retry the refused report: $(installed)"
pass "poll-custom-once reads both keys from the listing; watch-custom reconciles and retries refused writes"

# --- the image wiring ---------------------------------------------------------------------
python3 - "$TRAEFIK_ROLE/files/traefik-config.yml" <<'PY' || fail "traefik's file provider does not watch /etc/traefik/dynamic"
import sys, yaml
f = yaml.safe_load(open(sys.argv[1]))["providers"]["file"]
assert f == {"directory": "/etc/traefik/dynamic", "watch": True}, f
PY
grep -qF 'dest: /etc/traefik/dynamic/routing.yml' "$TRAEFIK_ROLE/tasks/main.yml" || fail "routing.yml is not in the watched directory"
grep -qF 'path: /etc/traefik/dynamic' "$TRAEFIK_ROLE/tasks/main.yml" || fail "the role does not create /etc/traefik/dynamic"
grep -qF 'TRAEFIK_DYNAMIC_DIR="${CALIMERO_TRAEFIK_DYNAMIC_DIR:-/etc/traefik/dynamic}"' "$TOOL" \
  || fail "the tool does not write into /etc/traefik/dynamic"
grep -qF 'CUSTOM_DIR="$TLS_DIR/custom"' "$TOOL" || fail "chains are not kept under /mnt/data/tls/custom"
grep -qF 'ExecStart=/usr/local/lib/calimero/tls-cert.sh watch-custom' "$TASKS" || fail "no unit runs watch-custom"
grep -qF 'dest: /etc/systemd/system/calimero-tls-cert-custom.service' "$TASKS" || fail "no calimero-tls-cert-custom.service"
[[ "$(grep -c 'systemctl enable .*traefik calimero-tls-cert calimero-tls-cert-custom$' "$TEMPLATE")" == 2 ]] \
  || fail "calimero-init must enable calimero-tls-cert-custom with traefik on both paths"
[[ "$(grep -c 'systemctl start --no-block .*traefik calimero-tls-cert calimero-tls-cert-custom$' "$TEMPLATE")" == 2 ]] \
  || fail "calimero-init must start calimero-tls-cert-custom with traefik on both paths"
grep -qF '"calimero-tls-cert-custom.service",' "$ROLE/files/vector-partial-merod.yaml" \
  || fail "vector does not collect calimero-tls-cert-custom.service"
pass "the image watches /etc/traefik/dynamic and installs, starts and collects calimero-tls-cert-custom"

echo "PASS: tls-custom-test"
