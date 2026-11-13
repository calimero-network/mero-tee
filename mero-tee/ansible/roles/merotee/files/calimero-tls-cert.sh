#!/usr/bin/env bash
# A publicly trusted certificate for the node's in-enclave TLS key.
#
# calimero-init generates the key at /mnt/data/tls/key.pem (EC P-256, on the
# encrypted data disk) and a self-signed placeholder cert.pem, which Traefik
# serves on :443 until this replaces it. The key never leaves the TD; mdma
# orders a certificate for it over ACME from a CSR (mdma
# dispatcher/app/node_certs.py). The exchange rides GCE, not the node's port:
#
#   publish  (calimero-init, every boot; `watch` retries it until it succeeds)
#     Build a CSR over key.pem naming exactly the `public-url` host and, when
#     `apps-domain` is set, `*.<apps-domain>` -- DNS names only -- and keep it at
#     csr.der, rebuilt only when that name set or the key changes, so its bytes
#     stay stable across boots. Take a TDX quote whose report data is
#       SHA-256(csr.der) || SHA-256("calimero.tee-attest.tls-csr.v1")
#     and PUT both, base64, as guest attributes calimero/tls-quote and
#     calimero/tls-csr. The quote is what tells mdma a genuine node of the
#     cluster holds the CSR's key; the host can write guest attributes too.
#
#   watch    (calimero-tls-cert.service)
#     Long-poll instance metadata `tls-cert` (PEM chain, leaf first), and while
#     it is unset the attributes directory, so a first chain lands at once.
#     Install a chain only when every certificate parses, each is signed by the
#     next, the leaf has not expired, and the leaf's public key is key.pem's:
#     the host can write metadata, so a chain for any other key is refused and
#     the current cert.pem kept. Installing writes cert.pem atomically (0644)
#     and restarts Traefik, which does not watch its certificate files.
#
#   watch-custom  (calimero-tls-cert-custom.service)
#     Custom domains: a package's served origin, e.g. kv.example.com (core
#     docs/specs/custom-domains.md, sections 7-9). Long-poll the instance
#     attributes for two keys mdma writes:
#       tls-custom-hosts  JSON array of hosts, mdma's record of the cluster's
#                         verified served origins
#       tls-cert-custom   JSON object {"<host>": "<PEM chain, leaf first>"}
#     For each listed host keep custom-csr/<host>.der, a CSR over the same
#     key.pem naming exactly CN=<host> and DNS:<host>, and publish them all as
#     guest attribute calimero/tls-csr-custom ({"<host>": "<base64 DER>"}). No
#     second quote: mdma orders only when the CSR's key is the one it attested
#     through calimero/tls-csr. Install a host's chain at custom/<host>.pem only
#     when it passes the checks above and its leaf names exactly that host,
#     list the installed chains in Traefik's dynamic file
#     /etc/traefik/dynamic/custom-certs.yml (picked by SNI; anything else gets
#     cert.pem), and report them as guest attribute calimero/tls-custom-installed
#     (a JSON array). A host no longer listed loses its chain, CSR and entry.
#     Traefik's file provider watches that directory: no restart. cert.pem, its
#     CSR and its quote are never touched here.
#
# Also, for tests and debugging: `names`, `report-data [CSR]`, `install FILE`,
# `poll-once [ETAG]`, `poll-custom-once [ETAG]`, `reconcile-custom HOSTS CERTS`,
# `custom-hosts HOSTS`. The paths below can be moved with environment variables
# so all of it runs outside a TD (scripts/ci/tests/tls-csr-test.sh).
set -euo pipefail

TLS_DIR="${CALIMERO_TLS_DIR:-/mnt/data/tls}"
METADATA_ROOT="${CALIMERO_METADATA_ROOT:-http://metadata.google.internal/computeMetadata/v1/instance}"
TSM_REPORT="${CALIMERO_TSM_REPORT:-/sys/kernel/config/tsm/report/calimero-tls-csr}"
STATE_DIR="${CALIMERO_TLS_STATE_DIR:-/run/calimero}"
# How long one long-poll of `tls-cert` waits for a change, in seconds.
POLL_TIMEOUT="${CALIMERO_TLS_POLL_TIMEOUT:-300}"
# Backoff after a metadata server error.
BACKOFF_MIN="${CALIMERO_TLS_BACKOFF_MIN:-5}"
BACKOFF_MAX="${CALIMERO_TLS_BACKOFF_MAX:-300}"
# How often `watch` retries a publish that has not succeeded on this boot.
REPUBLISH_EVERY="${CALIMERO_TLS_REPUBLISH_EVERY:-300}"

METADATA_HEADER="Metadata-Flavor: Google"
CSR_BINDING_DOMAIN="calimero.tee-attest.tls-csr.v1"
KEY="$TLS_DIR/key.pem"
CSR="$TLS_DIR/csr.der"
CERT="$TLS_DIR/cert.pem"
# Set once this boot's CSR and quote are published; /run is a tmpfs.
PUBLISHED="$STATE_DIR/tls-csr-published"
# Custom domains: one chain per host beside key.pem, its CSR, and the Traefik
# dynamic file that lists them (the file provider watches its directory).
CUSTOM_DIR="$TLS_DIR/custom"
CUSTOM_CSR_DIR="$TLS_DIR/custom-csr"
TRAEFIK_DYNAMIC_DIR="${CALIMERO_TRAEFIK_DYNAMIC_DIR:-/etc/traefik/dynamic}"
TRAEFIK_CUSTOM="$TRAEFIK_DYNAMIC_DIR/custom-certs.yml"
# core's MAX_SERVED_ORIGINS: no cluster holds more served origins than this.
MAX_CUSTOM_HOSTS="${CALIMERO_TLS_MAX_CUSTOM_HOSTS:-64}"

WORK=""
cleanup() { [[ -z "$WORK" ]] || rm -rf "$WORK"; }
trap cleanup EXIT
workdir() { [[ -n "$WORK" ]] || WORK="$(mktemp -d)"; }

log() { echo "[$(date -Iseconds)] calimero-tls-cert: $*" >&2; }

# etag_of HEADERS_FILE: the ETag in a curl -D dump, or nothing.
etag_of() { awk -F': *' 'tolower($1) == "etag" { gsub(/[\r\n]/, "", $2); print $2; exit }' "$1"; }

meta() {
  curl -sf --max-time 30 -H "$METADATA_HEADER" "$METADATA_ROOT/attributes/$1" 2>/dev/null \
    | tr -d '\r\n' || true
}

# A DNS name a public CA will issue for: dot-separated LDH labels, no IP literal.
valid_dns_name() {
  local name="$1" label='[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
  (( ${#name} <= 253 )) && [[ "$name" =~ ^${label}(\.${label})+$ ]] && ! [[ "$name" =~ ^[0-9.]+$ ]]
}

# The names the CSR asks for, one per line: the `public-url` host, then
# `*.<apps-domain>` when set. mdma compares them, lowercased, with its own
# record of the node and refuses any other set, so nothing else is added.
tls_names() {
  local url apps authority host
  url="$(meta public-url)"
  apps="$(meta apps-domain)"
  if ! [[ "$url" =~ ^[Hh][Tt][Tt][Pp][Ss]://([^/?#]+) ]]; then
    log "public-url '${url}' is not an https:// URL; no certificate to request"
    return 1
  fi
  authority="${BASH_REMATCH[1]}"
  host="${authority##*@}"
  host="${host%:*}"
  host="${host,,}"
  if ! valid_dns_name "$host"; then
    log "public-url host '${host}' is not a DNS name a certificate can be issued for"
    return 1
  fi
  printf '%s\n' "$host"
  apps="${apps,,}"
  apps="${apps%.}"
  if [[ -n "$apps" ]]; then
    if ! valid_dns_name "$apps"; then
      log "apps-domain '${apps}' is not a DNS name; no certificate to request"
      return 1
    fi
    printf '*.%s\n' "$apps"
  fi
}

# SHA-256 of a public key's SubjectPublicKeyInfo, read as PEM on stdin.
spki_sha256() { openssl pkey -pubin -outform DER | sha256sum | cut -c1-64; }
key_spki_sha256() { openssl pkey -in "$KEY" -pubout | spki_sha256; }

# csr_matches HOST SAN [FILE]: FILE (csr.der by default) is a well-signed
# request over key.pem for exactly CN=HOST and subjectAltName SAN
# (`DNS:a,DNS:b`).
csr_matches() {
  local host="$1" san="$2" CSR="${3:-$CSR}" text subject have
  [[ -s "$CSR" ]] || return 1
  openssl req -inform DER -in "$CSR" -noout -verify >/dev/null 2>&1 || return 1
  subject="$(openssl req -inform DER -in "$CSR" -noout -subject -nameopt RFC2253 2>/dev/null)" || return 1
  [[ "$subject" == "subject=CN=$host" ]] || return 1
  text="$(openssl req -inform DER -in "$CSR" -noout -text 2>/dev/null)" || return 1
  have="$(awk '/X509v3 Subject Alternative Name/{getline; gsub(/^[ \t]+|[ \t]+$/, ""); print; exit}' <<<"$text")"
  [[ "$have" == "${san//,/, }" ]] || return 1
  [[ "$(openssl req -inform DER -in "$CSR" -noout -pubkey | spki_sha256)" == "$(key_spki_sha256)" ]]
}

# ensure_csr NAME...: csr.der names exactly NAME... (the first is the CN).
ensure_csr() {
  local host="$1" san="" name tmp
  for name in "$@"; do san+="${san:+,}DNS:${name}"; done
  if csr_matches "$host" "$san"; then
    log "CSR for ${*} unchanged; reusing $CSR"
    return 0
  fi
  tmp="$(mktemp "$TLS_DIR/.csr.XXXXXX")"
  # -config /dev/null: only the extension asked for here, whatever the
  # system openssl.cnf would add.
  if ! openssl req -new -config /dev/null -sha256 -key "$KEY" -subj "/CN=${host}" \
      -addext "subjectAltName=${san}" -outform DER -out "$tmp"; then
    rm -f "$tmp"
    log "could not build a CSR over $KEY"
    return 1
  fi
  chmod 0644 "$tmp"
  mv -f "$tmp" "$CSR"
  log "built a CSR for ${*} at $CSR"
}

# The quote's 64 bytes of report data, raw, on stdout.
report_data() {
  local csr="${1:-$CSR}"
  openssl dgst -sha256 -binary <"$csr"
  printf '%s' "$CSR_BINDING_DOMAIN" | openssl dgst -sha256 -binary
}

# take_quote REPORT_DATA_FILE: a TDX quote over it from configfs-tsm, raw, on
# stdout (the same interface mero-kms and the probe image take quotes through).
take_quote() {
  local inblob="$1"
  if [[ -z "${CALIMERO_TSM_REPORT:-}" ]]; then
    modprobe tdx_guest 2>/dev/null || true
    mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
  fi
  mkdir -p "$TSM_REPORT"
  # One write of all 64 bytes, then the quote over them.
  cat "$inblob" >"$TSM_REPORT/inblob"
  cat "$TSM_REPORT/outblob"
}

put_guest_attribute() {
  local name="$1" value_file="$2"
  curl -sSf --max-time 30 -X PUT -H "$METADATA_HEADER" --data-binary "@${value_file}" \
    "$METADATA_ROOT/guest-attributes/calimero/${name}" >/dev/null
}

cmd_publish() {
  local names_out
  local -a names
  [[ -s "$KEY" ]] || { log "no TLS key at $KEY; nothing to publish"; return 1; }
  names_out="$(tls_names)" || return 1
  mapfile -t names <<<"$names_out"
  ensure_csr "${names[@]}" || return 1

  workdir
  report_data "$CSR" >"$WORK/report-data"
  [[ "$(wc -c <"$WORK/report-data")" -eq 64 ]] || { log "report data is not 64 bytes"; return 1; }
  if ! take_quote "$WORK/report-data" >"$WORK/quote" || [[ ! -s "$WORK/quote" ]]; then
    log "no TDX quote from configfs-tsm at $TSM_REPORT"
    return 1
  fi
  base64 -w0 <"$WORK/quote" >"$WORK/quote.b64"
  base64 -w0 <"$CSR" >"$WORK/csr.b64"
  # The quote first: if mdma reads between the two writes, a new quote beside
  # the old CSR is refused for its names, not counted as a bad quote.
  if ! put_guest_attribute tls-quote "$WORK/quote.b64" || ! put_guest_attribute tls-csr "$WORK/csr.b64"; then
    log "could not write the calimero/tls-csr and tls-quote guest attributes \
(is enable-guest-attributes set on the instance?)"
    return 1
  fi
  mkdir -p "$STATE_DIR"
  : >"$PUBLISHED"
  log "published the CSR for ${names[*]} and its quote as guest attributes calimero/tls-csr, calimero/tls-quote"
}

# refuse MESSAGE: an install that does not happen. cert.pem is left as it is.
refuse() { log "REFUSED the tls-cert chain: $*; keeping the current $CERT"; return 1; }

# chain_problem SRC DIR: split the PEM chain in SRC (leaf first) into DIR as
# 1.norm, 2.norm, ... and DIR/chain (the certificates alone, re-encoded).
# Prints why the chain cannot be installed and fails when a certificate does
# not parse, one is not signed by the next, the leaf has expired or its key is
# not key.pem's. Both the node certificate and the custom hosts' use it.
chain_problem() {
  local src="$1" dir="$2" count i
  [[ -s "$src" ]] || { echo "it is empty"; return 1; }
  rm -rf "$dir"
  mkdir "$dir"
  awk -v dir="$dir" '
    /-----BEGIN CERTIFICATE-----/ { n++; on = 1 }
    on { print > (dir "/" n ".pem") }
    /-----END CERTIFICATE-----/ { on = 0 }
  ' "$src"
  count="$(find "$dir" -name '*.pem' | wc -l)"
  (( count >= 1 )) || { echo "it holds no PEM certificate"; return 1; }
  : >"$dir/chain"
  for (( i = 1; i <= count; i++ )); do
    openssl x509 -in "$dir/$i.pem" -out "$dir/$i.norm" 2>/dev/null \
      || { echo "certificate $i of $count does not parse"; return 1; }
    cat "$dir/$i.norm" >>"$dir/chain"
  done
  if [[ "$(openssl x509 -in "$dir/1.norm" -noout -pubkey | spki_sha256)" != "$(key_spki_sha256)" ]]; then
    echo "the leaf certificate is not for this node's key ($KEY)"
    return 1
  fi
  for (( i = 1; i < count; i++ )); do
    openssl verify -partial_chain -no_check_time -CAfile "$dir/$((i + 1)).norm" "$dir/$i.norm" >/dev/null 2>&1 \
      || { echo "certificate $i is not signed by certificate $((i + 1))"; return 1; }
  done
  openssl x509 -in "$dir/1.norm" -noout -checkend 0 >/dev/null \
    || { echo "the leaf certificate has expired"; return 1; }
}

# cmd_install FILE: install the PEM chain in FILE (leaf first) as cert.pem.
cmd_install() {
  local src="$1" dir why
  [[ -s "$KEY" ]] || { log "no TLS key at $KEY"; return 1; }
  workdir
  dir="$WORK/chain"
  if ! why="$(chain_problem "$src" "$dir")"; then
    refuse "$why"
    return 1
  fi

  if cmp -s "$dir/chain" "$CERT"; then
    log "the tls-cert chain is already installed at $CERT"
    return 0
  fi
  local tmp
  tmp="$(mktemp "$TLS_DIR/.cert.XXXXXX")"
  cat "$dir/chain" >"$tmp"
  chmod 0644 "$tmp"
  mv -f "$tmp" "$CERT"
  log "installed the certificate for $(openssl x509 -in "$dir/1.norm" -noout -subject -nameopt RFC2253) \
($(openssl x509 -in "$dir/1.norm" -noout -enddate)) at $CERT; restarting traefik"
  systemctl restart traefik >&2 || log "WARN: could not restart traefik; it serves the new certificate from its next start"
}

# cmd_poll_once [LAST_ETAG]: one (long) poll of `tls-cert`. Prints the ETag it
# saw; installs the chain when the ETag differs from LAST_ETAG. Exit 0 on a
# value (installed or not), 2 while `tls-cert` is unset, 1 on any other error.
cmd_poll_once() {
  local last="${1:-NONE}" code etag
  workdir
  # last_etag NONE never matches, so the first poll returns at once.
  code="$(curl -sS --max-time $((POLL_TIMEOUT + 30)) -H "$METADATA_HEADER" \
    -D "$WORK/headers" -o "$WORK/body" -w '%{http_code}' \
    "$METADATA_ROOT/attributes/tls-cert?wait_for_change=true&last_etag=${last}&timeout_sec=${POLL_TIMEOUT}")" \
    || code=000
  case "$code" in
    200)
      etag="$(etag_of "$WORK/headers")"
      printf '%s\n' "${etag:-NONE}"
      if [[ -z "$etag" || "$etag" != "$last" ]]; then
        cmd_install "$WORK/body" >&2 || true
      fi
      return 0
      ;;
    404) return 2 ;;
    *)
      log "metadata server answered ${code} for tls-cert"
      return 1
      ;;
  esac
}

# wait_attributes [LAST_ETAG]: long-poll the instance attributes directory
# until its ETag differs from LAST_ETAG (NONE answers at once); prints it.
wait_attributes() {
  local code etag
  code="$(curl -sS --max-time $((POLL_TIMEOUT + 30)) -H "$METADATA_HEADER" \
    -D "$WORK/attrs-headers" -o /dev/null -w '%{http_code}' \
    "$METADATA_ROOT/attributes/?recursive=true&wait_for_change=true&last_etag=${1:-NONE}&timeout_sec=${POLL_TIMEOUT}")" \
    || code=000
  if [[ "$code" != 200 ]]; then
    log "metadata server answered ${code} for the instance attributes"
    return 1
  fi
  etag="$(etag_of "$WORK/attrs-headers")"
  printf '%s\n' "${etag:-NONE}"
}

cmd_watch() {
  local last=NONE dir=NONE backoff="$BACKOFF_MIN" next_publish=0 out rc
  # Made here, so each poll's subshell reuses it rather than leaving its own.
  workdir
  while true; do
    if [[ ! -e "$PUBLISHED" ]] && (( SECONDS >= next_publish )); then
      cmd_publish || log "WARN: CSR not published yet; retrying in ${REPUBLISH_EVERY}s"
      next_publish=$((SECONDS + REPUBLISH_EVERY))
    fi
    rc=0
    out="$(cmd_poll_once "$last")" || rc=$?
    case "$rc" in
      0)
        last="${out:-NONE}"
        backoff="$BACKOFF_MIN"
        sleep 1
        ;;
      2)
        # Unset: long-poll the attributes rather than sleep. dir was read before
        # this 404, so a chain written since then ends the wait at once.
        last=NONE
        if out="$(wait_attributes "$dir")"; then
          dir="$out"
          backoff="$BACKOFF_MIN"
          sleep 1
        else
          sleep "$backoff"
          backoff=$(( backoff * 2 > BACKOFF_MAX ? BACKOFF_MAX : backoff * 2 ))
        fi
        ;;
      *)
        sleep "$backoff"
        backoff=$(( backoff * 2 > BACKOFF_MAX ? BACKOFF_MAX : backoff * 2 ))
        ;;
    esac
  done
}

# --- custom domains ------------------------------------------------------------
# A package's served origin (core docs/specs/custom-domains.md, sections 7-9)
# gets one certificate per host, for the same key.pem: no second key, no second
# quote. mdma accepts a custom CSR only when its key is the one it saw attested
# in calimero/tls-csr above, so only this TD can produce one.

# custom_hosts_from VALUE: the hosts in a `tls-custom-hosts` value (a JSON array
# of strings), lowercased, deduplicated and sorted, one per line. An entry that
# is not a DNS name a CA issues for (a wildcard, an address, anything with a
# slash) is logged and left out; a value that is not such an array, or names
# more than MAX_CUSTOM_HOSTS, fails, and the caller changes nothing.
custom_hosts_from() {
  local value="$1" out name
  local -a kept=()
  [[ -n "$value" ]] || return 0
  out="$(python3 -c '
import json, sys
v = json.loads(sys.argv[1])
if not isinstance(v, list) or not all(isinstance(h, str) for h in v):
    sys.exit("not a JSON array of strings")
for h in v:
    h = h.strip().lower()
    if h.endswith("."):
        h = h[:-1]
    if "\n" in h or not h:
        continue
    print(h)
' "$value" 2>/dev/null)" || { log "tls-custom-hosts is not a JSON array of host names"; return 1; }
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    if valid_dns_name "$name"; then
      kept+=("$name")
    else
      log "tls-custom-hosts names '${name}', which is not a DNS name a certificate can be issued for; left out"
    fi
  done <<<"$out"
  (( ${#kept[@]} > 0 )) || return 0
  mapfile -t kept < <(printf '%s\n' "${kept[@]}" | sort -u)
  if (( ${#kept[@]} > MAX_CUSTOM_HOSTS )); then
    log "tls-custom-hosts names ${#kept[@]} hosts, more than ${MAX_CUSTOM_HOSTS}; ignoring it"
    return 1
  fi
  printf '%s\n' "${kept[@]}"
}

# json_object_of KEY=FILE...: a JSON object mapping each KEY to the contents of
# FILE (base64 or PEM text), keys sorted, on stdout.
json_object_of() {
  python3 -c '
import json, sys
out = {}
for arg in sys.argv[1:]:
    k, _, path = arg.partition("=")
    with open(path, encoding="ascii") as f:
        out[k] = f.read()
print(json.dumps(out, sort_keys=True, separators=(",", ":")))
' "$@"
}

json_array_of() {
  python3 -c 'import json, sys; print(json.dumps(sorted(sys.argv[1:]), separators=(",", ":")))' "$@"
}

# put_once NAME FILE: write guest attribute calimero/NAME, unless this boot
# already wrote exactly FILE's contents there. A failed write is retried by the
# next reconcile.
put_once() {
  local name="$1" file="$2" last="$STATE_DIR/$1.last"
  if cmp -s "$file" "$last"; then
    return 0
  fi
  if ! put_guest_attribute "$name" "$file"; then
    log "could not write guest attribute calimero/${name}; retrying"
    return 1
  fi
  mkdir -p "$STATE_DIR"
  cp "$file" "$last"
  log "published guest attribute calimero/${name}"
}

# publish_custom_csrs HOST...: keep custom-csr/<host>.der, a CSR over key.pem
# naming exactly CN=<host> and DNS:<host>, for each HOST (rebuilt only when the
# key changes), drop the others, and publish them all as calimero/tls-csr-custom
# ({"<host>": "<base64 DER>"}; `{}` for none).
publish_custom_csrs() {
  local host file tmp
  local -a pairs=()
  mkdir -p "$CUSTOM_CSR_DIR"
  for file in "$CUSTOM_CSR_DIR"/*.der; do
    [[ -e "$file" ]] || continue
    host="$(basename "$file" .der)"
    if ! printf '%s\n' "$@" | grep -qxF -- "$host"; then
      rm -f "$file"
      log "dropped the CSR for ${host}: no longer in tls-custom-hosts"
    fi
  done
  for host in "$@"; do
    file="$CUSTOM_CSR_DIR/$host.der"
    if ! csr_matches "$host" "DNS:${host}" "$file"; then
      tmp="$(mktemp "$CUSTOM_CSR_DIR/.csr.XXXXXX")"
      if ! openssl req -new -config /dev/null -sha256 -key "$KEY" -subj "/CN=${host}" \
          -addext "subjectAltName=DNS:${host}" -outform DER -out "$tmp" 2>/dev/null; then
        rm -f "$tmp"
        log "could not build a CSR for ${host} over $KEY"
        return 1
      fi
      chmod 0644 "$tmp"
      mv -f "$tmp" "$file"
      log "built a CSR for ${host} at $file"
    fi
    base64 -w0 <"$file" >"$WORK/custom-csr-$host.b64"
    pairs+=("$host=$WORK/custom-csr-$host.b64")
  done
  json_object_of "${pairs[@]}" >"$WORK/tls-csr-custom.json"
  put_once tls-csr-custom "$WORK/tls-csr-custom.json"
}

# custom_chain_problem HOST SRC DIR: chain_problem, and the leaf names exactly
# HOST (subjectAltName DNS:HOST and nothing else; a CN, if any, is HOST). A
# chain filed under one host that names another is what a host writing
# metadata could swap in.
custom_chain_problem() {
  local host="$1" src="$2" dir="$3" san cn
  chain_problem "$src" "$dir" || return 1
  san="$(openssl x509 -in "$dir/1.norm" -noout -ext subjectAltName 2>/dev/null \
    | awk 'NR > 1 { gsub(/^[ \t]+|[ \t]+$/, ""); print }')"
  if [[ "$san" != "DNS:${host}" ]]; then
    echo "the leaf names ${san:-no subjectAltName}, not exactly DNS:${host}"
    return 1
  fi
  cn="$(openssl x509 -in "$dir/1.norm" -noout -subject -nameopt RFC2253 2>/dev/null)"
  cn="${cn#subject=}"
  if [[ -n "$cn" && "$cn" != "CN=${host}" ]]; then
    echo "the leaf's subject is ${cn}, not CN=${host}"
    return 1
  fi
}

# install_custom_certs CERTS_JSON HOST...: for each HOST, install the chain
# CERTS_JSON (a `tls-cert-custom` value) files under it as custom/<host>.pem
# when custom_chain_problem finds nothing; otherwise keep the installed one
# while it still passes. Remove every installed chain for a host not listed.
# Prints the hosts with a chain installed, one per line.
install_custom_certs() {
  local certs="$1" host file why
  shift
  local split="$WORK/custom-in"
  rm -rf "$split"
  mkdir -p "$split" "$CUSTOM_DIR"
  # Only keys that are listed hosts become file names (already DNS names).
  if [[ -n "$certs" ]] && ! python3 -c '
import json, os, sys
d = json.loads(sys.argv[1])
if not isinstance(d, dict):
    sys.exit("not a JSON object")
hosts = set(sys.argv[3:])
for k, v in d.items():
    if k not in hosts or not isinstance(v, str):
        print(f"ignored an entry not in tls-custom-hosts: {k[:80]!r}", file=sys.stderr)
        continue
    with open(os.path.join(sys.argv[2], k + ".pem"), "w", encoding="utf-8") as f:
        f.write(v)
' "$certs" "$split" "$@" 2>"$WORK/custom-in.err"; then
    log "tls-cert-custom is not a JSON object of PEM chains; keeping what is installed"
    : >"$WORK/custom-in.err"
    rm -rf "$split"
    mkdir -p "$split"
  fi
  while IFS= read -r why; do [[ -z "$why" ]] || log "tls-cert-custom: $why"; done <"$WORK/custom-in.err"

  for file in "$CUSTOM_DIR"/*.pem; do
    [[ -e "$file" ]] || continue
    host="$(basename "$file" .pem)"
    if ! printf '%s\n' "$@" | grep -qxF -- "$host"; then
      rm -f "$file"
      log "removed the certificate for ${host}: no longer in tls-custom-hosts"
    fi
  done

  for host in "$@"; do
    file="$CUSTOM_DIR/$host.pem"
    if [[ -s "$split/$host.pem" ]]; then
      if why="$(custom_chain_problem "$host" "$split/$host.pem" "$WORK/custom-chain")"; then
        if ! cmp -s "$WORK/custom-chain/chain" "$file"; then
          local tmp
          tmp="$(mktemp "$CUSTOM_DIR/.cert.XXXXXX")"
          cat "$WORK/custom-chain/chain" >"$tmp"
          chmod 0644 "$tmp"
          mv -f "$tmp" "$file"
          log "installed the certificate for ${host} \
($(openssl x509 -in "$WORK/custom-chain/1.norm" -noout -enddate)) at $file"
        fi
        printf '%s\n' "$host"
        continue
      fi
      log "REFUSED the tls-cert-custom chain for ${host}: ${why}"
    fi
    [[ -e "$file" ]] || continue
    # What is installed must still pass: not expired, still this key's.
    if why="$(custom_chain_problem "$host" "$file" "$WORK/custom-chain")"; then
      printf '%s\n' "$host"
    else
      rm -f "$file"
      log "removed the installed certificate for ${host}: ${why}"
    fi
  done
}

# render_custom_traefik HOST...: Traefik's dynamic file listing each HOST's
# chain with key.pem. Traefik picks a certificate by SNI and falls back to the
# default store's (cert.pem, the node certificate). The chain is written into
# the file rather than named by path: the file provider reloads only when the
# configuration it reads differs, and a renewal at the same path would not.
# Written atomically, only when it changes, so the directory watch reloads
# Traefik without a restart.
render_custom_traefik() {
  local host tmp
  mkdir -p "$TRAEFIK_DYNAMIC_DIR"
  tmp="$(mktemp "$(dirname "$TRAEFIK_DYNAMIC_DIR")/.custom-certs.XXXXXX")"
  {
    echo "# Written by calimero-tls-cert-custom.service from tls-cert-custom; do not edit."
    if (( $# == 0 )); then
      echo "tls:"
      echo "  certificates: []"
    else
      echo "tls:"
      echo "  certificates:"
      for host in "$@"; do
        echo "    # ${host}"
        echo "    - certFile: |"
        sed 's/^/        /' "$CUSTOM_DIR/$host.pem"
        echo "      keyFile: ${KEY}"
      done
    fi
  } >"$tmp"
  chmod 0644 "$tmp"
  if cmp -s "$tmp" "$TRAEFIK_CUSTOM"; then
    rm -f "$tmp"
    return 0
  fi
  mv -f "$tmp" "$TRAEFIK_CUSTOM"
  log "wrote $TRAEFIK_CUSTOM for: ${*:-no custom hosts}"
}

# cmd_reconcile_custom HOSTS_VALUE CERTS_VALUE: one pass over the two metadata
# values. Fails (and the watcher retries) when a guest attribute could not be
# written; a bad tls-custom-hosts changes nothing.
cmd_reconcile_custom() {
  local hosts_value="$1" certs_value="$2" out rc=0
  local -a hosts installed
  [[ -s "$KEY" ]] || { log "no TLS key at $KEY; no custom certificates"; return 1; }
  workdir
  out="$(custom_hosts_from "$hosts_value")" || return 1
  hosts=()
  [[ -z "$out" ]] || mapfile -t hosts <<<"$out"
  publish_custom_csrs "${hosts[@]}" || rc=1
  out="$(install_custom_certs "$certs_value" "${hosts[@]}")"
  installed=()
  [[ -z "$out" ]] || mapfile -t installed <<<"$out"
  render_custom_traefik "${installed[@]}"
  json_array_of "${installed[@]}" >"$WORK/tls-custom-installed.json"
  put_once tls-custom-installed "$WORK/tls-custom-installed.json" || rc=1
  return "$rc"
}

# cmd_poll_custom_once [LAST_ETAG]: one (long) poll of the instance attributes
# directory, which changes when tls-custom-hosts or tls-cert-custom (or any
# other key) does. Prints the ETag it saw and reconciles when it differs from
# LAST_ETAG (RETRY never matches, and asks for an answer at once). Only the two
# values are kept; the whole listing is deleted as soon as they are read. Exit
# 0 when reconciled or unchanged, 1 on any error.
cmd_poll_custom_once() {
  local last="${1:-NONE}" wait_etag code etag
  workdir
  wait_etag="$last"
  [[ "$last" != RETRY ]] || wait_etag=NONE
  code="$(curl -sS --max-time $((POLL_TIMEOUT + 30)) -H "$METADATA_HEADER" \
    -D "$WORK/custom-headers" -o "$WORK/custom-attrs" -w '%{http_code}' \
    "$METADATA_ROOT/attributes/?recursive=true&wait_for_change=true&last_etag=${wait_etag}&timeout_sec=${POLL_TIMEOUT}")" \
    || code=000
  if [[ "$code" != 200 ]]; then
    rm -f "$WORK/custom-attrs"
    log "metadata server answered ${code} for the instance attributes"
    return 1
  fi
  if ! python3 -c '
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
if not isinstance(d, dict):
    sys.exit(1)
for k in ("tls-custom-hosts", "tls-cert-custom"):
    v = d.get(k, "")
    with open(sys.argv[2] + "/" + k, "w", encoding="utf-8") as f:
        f.write(v if isinstance(v, str) else "")
' "$WORK/custom-attrs" "$WORK" 2>/dev/null; then
    rm -f "$WORK/custom-attrs"
    log "the instance attributes are not a JSON object"
    return 1
  fi
  rm -f "$WORK/custom-attrs"
  etag="$(etag_of "$WORK/custom-headers")"
  printf '%s\n' "${etag:-NONE}"
  if [[ -z "$etag" || "$etag" != "$last" ]]; then
    cmd_reconcile_custom "$(cat "$WORK/tls-custom-hosts")" "$(cat "$WORK/tls-cert-custom")" >&2 || return 1
  fi
  return 0
}

cmd_watch_custom() {
  local last=NONE backoff="$BACKOFF_MIN" out rc
  workdir
  while true; do
    rc=0
    out="$(cmd_poll_custom_once "$last")" || rc=$?
    if (( rc == 0 )); then
      last="${out:-NONE}"
      backoff="$BACKOFF_MIN"
      sleep 1
    else
      # Reconcile again on the next answer, changed or not.
      [[ -z "$out" ]] || last=RETRY
      sleep "$backoff"
      backoff=$(( backoff * 2 > BACKOFF_MAX ? BACKOFF_MAX : backoff * 2 ))
    fi
  done
}

case "${1:-}" in
  publish) cmd_publish ;;
  watch) cmd_watch ;;
  install) cmd_install "${2:?install FILE}" ;;
  poll-once) cmd_poll_once "${2:-NONE}" ;;
  watch-custom) cmd_watch_custom ;;
  poll-custom-once) cmd_poll_custom_once "${2:-NONE}" ;;
  reconcile-custom) cmd_reconcile_custom "${2-}" "${3-}" ;;
  custom-hosts) custom_hosts_from "${2-}" ;;
  names) tls_names ;;
  report-data) report_data "${2:-$CSR}" ;;
  *)
    echo "usage: $0 publish|watch|install FILE|poll-once [ETAG]|names|report-data [CSR]" >&2
    echo "       $0 watch-custom|poll-custom-once [ETAG]|reconcile-custom HOSTS CERTS|custom-hosts HOSTS" >&2
    exit 64
    ;;
esac
