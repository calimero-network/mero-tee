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
#     Long-poll instance metadata `tls-cert` (PEM chain, leaf first). Install a
#     chain only when every certificate parses, each is signed by the next, the
#     leaf has not expired, and the leaf's public key is key.pem's: the host can
#     write metadata, so a chain for any other key is refused and the current
#     cert.pem kept. Installing writes cert.pem atomically (0644) and restarts
#     Traefik, which does not watch its certificate files.
#
# Also, for tests and debugging: `names`, `report-data [CSR]`, `install FILE`,
# `poll-once [ETAG]`. The paths below can be moved with environment variables
# so all of it runs outside a TD (scripts/ci/tests/tls-csr-test.sh).
set -euo pipefail

TLS_DIR="${CALIMERO_TLS_DIR:-/mnt/data/tls}"
METADATA_ROOT="${CALIMERO_METADATA_ROOT:-http://metadata.google.internal/computeMetadata/v1/instance}"
TSM_REPORT="${CALIMERO_TSM_REPORT:-/sys/kernel/config/tsm/report/calimero-tls-csr}"
STATE_DIR="${CALIMERO_TLS_STATE_DIR:-/run/calimero}"
# How long one long-poll of `tls-cert` waits for a change, in seconds.
POLL_TIMEOUT="${CALIMERO_TLS_POLL_TIMEOUT:-300}"
# Backoff while `tls-cert` is unset (404) or the metadata server errors.
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

WORK=""
cleanup() { [[ -z "$WORK" ]] || rm -rf "$WORK"; }
trap cleanup EXIT
workdir() { [[ -n "$WORK" ]] || WORK="$(mktemp -d)"; }

log() { echo "[$(date -Iseconds)] calimero-tls-cert: $*" >&2; }

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

# csr_matches HOST SAN: csr.der is a well-signed request over key.pem for
# exactly CN=HOST and subjectAltName SAN (`DNS:a,DNS:b`).
csr_matches() {
  local host="$1" san="$2" text subject have
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

# cmd_install FILE: install the PEM chain in FILE (leaf first) as cert.pem.
cmd_install() {
  local src="$1" dir count i
  [[ -s "$KEY" ]] || { log "no TLS key at $KEY"; return 1; }
  [[ -s "$src" ]] || { refuse "it is empty"; return 1; }
  workdir
  dir="$WORK/chain"
  rm -rf "$dir"
  mkdir "$dir"
  awk -v dir="$dir" '
    /-----BEGIN CERTIFICATE-----/ { n++; on = 1 }
    on { print > (dir "/" n ".pem") }
    /-----END CERTIFICATE-----/ { on = 0 }
  ' "$src"
  count="$(find "$dir" -name '*.pem' | wc -l)"
  (( count >= 1 )) || { refuse "it holds no PEM certificate"; return 1; }
  : >"$dir/chain"
  for (( i = 1; i <= count; i++ )); do
    openssl x509 -in "$dir/$i.pem" -out "$dir/$i.norm" 2>/dev/null \
      || { refuse "certificate $i of $count does not parse"; return 1; }
    cat "$dir/$i.norm" >>"$dir/chain"
  done
  if [[ "$(openssl x509 -in "$dir/1.norm" -noout -pubkey | spki_sha256)" != "$(key_spki_sha256)" ]]; then
    refuse "the leaf certificate is not for this node's key ($KEY)"
    return 1
  fi
  for (( i = 1; i < count; i++ )); do
    openssl verify -partial_chain -no_check_time -CAfile "$dir/$((i + 1)).norm" "$dir/$i.norm" >/dev/null 2>&1 \
      || { refuse "certificate $i is not signed by certificate $((i + 1))"; return 1; }
  done
  openssl x509 -in "$dir/1.norm" -noout -checkend 0 >/dev/null \
    || { refuse "the leaf certificate has expired"; return 1; }

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
      etag="$(awk -F': *' 'tolower($1) == "etag" { gsub(/[\r\n]/, "", $2); print $2; exit }' "$WORK/headers")"
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

cmd_watch() {
  local last=NONE backoff="$BACKOFF_MIN" next_publish=0 out rc
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
        last=NONE
        sleep "$backoff"
        backoff=$(( backoff * 2 > BACKOFF_MAX ? BACKOFF_MAX : backoff * 2 ))
        ;;
      *)
        sleep "$backoff"
        backoff=$(( backoff * 2 > BACKOFF_MAX ? BACKOFF_MAX : backoff * 2 ))
        ;;
    esac
  done
}

case "${1:-}" in
  publish) cmd_publish ;;
  watch) cmd_watch ;;
  install) cmd_install "${2:?install FILE}" ;;
  poll-once) cmd_poll_once "${2:-NONE}" ;;
  names) tls_names ;;
  report-data) report_data "${2:-$CSR}" ;;
  *)
    echo "usage: $0 publish|watch|install FILE|poll-once [ETAG]|names|report-data [CSR]" >&2
    exit 64
    ;;
esac
