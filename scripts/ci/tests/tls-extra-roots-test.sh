#!/usr/bin/env bash
# Extra TLS roots: a debug image trusts the Let's Encrypt staging roots for
# HTTPS to its peers (merod --tls-extra-roots); the production image never does.
#
# What fails quietly without this test:
#   * the production image (locked-read-only) gets the roots file or the
#     MEROD_TLS_EXTRA_ROOTS line, so prod nodes trust the staging CA;
#   * a debug image loses them, so no node joins a running debug cluster;
#   * a merod without the flag is given the variable and ignores it, so the
#     node cannot join and nothing says why;
#   * the shipped bundle drifts from the four published staging roots.
#
# The merotee role is rendered for each profile (scripts/image/render_role_tree.py,
# what the image builds use), and the rendered block is run with merod and the
# env file stubbed.
#
# Usage: scripts/ci/tests/tls-extra-roots-test.sh
# The stubs are used by the block run through eval.
# shellcheck disable=SC2034,SC2329
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TOOL="${REPO_ROOT}/scripts/image/render_role_tree.py"
ROOTS="${REPO_ROOT}/mero-tee/ansible/roles/merotee/files/le-staging-roots.crt"
ROOTS_IN_IMAGE="usr/local/lib/calimero/le-staging-roots.crt"
INIT_IN_IMAGE="usr/local/lib/calimero/init.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# The bundle is exactly the four published staging roots
# (https://letsencrypt.org/docs/staging-environment/).
expected="9B:2A:33:9F:E6:A3:E8:55:85:C4:CD:75:53:6C:B8:C1:CF:7C:D6:03:B9:A6:4B:EC:25:21:85:8A:E4:8D:A8:5D
B5:9B:FC:0B:A5:2D:AF:84:98:53:B7:32:4A:91:E8:2F:03:1D:B3:39:7F:35:64:41:57:35:2C:DE:63:84:B5:6C
E7:05:70:A9:89:F8:56:5A:AB:DF:7C:AE:27:AB:D1:62:18:72:D6:A3:F8:11:E3:FE:F2:7E:3D:BA:02:91:21:98
EF:11:5F:B5:9E:04:0F:F3:9D:15:FD:8F:3E:F5:40:63:C7:04:32:1D:83:CB:08:12:13:27:2F:77:D3:09:16:72"
mkdir -p "$work/certs"
awk -v dir="$work/certs" '/-----BEGIN CERTIFICATE-----/{n++; on=1} on{print >> (dir "/cert" n ".pem")} /-----END CERTIFICATE-----/{on=0}' "$ROOTS"
got="$(for c in "$work"/certs/cert*.pem; do openssl x509 -in "$c" -noout -fingerprint -sha256 | cut -d= -f2; done | sort)"
[[ "$got" == "$expected" ]] || fail "le-staging-roots.crt is not the four Let's Encrypt staging roots:
$got"

# render PROFILE: the node playbook's merotee role as that profile's image holds it.
render() {
  python3 "$TOOL" "${REPO_ROOT}/mero-tee/playbook.yml" --out "$work/$1" --manifest "$work/$1.json" \
    --cache "$work/empty" -e "lockdown_profile=$1" -e image_version=0.0.0 -e cpu_architecture=amd64 \
    -e merod_version=0.0.0 --role merotee >/dev/null || fail "the merotee role does not render for $1"
  [[ -r "$work/$1/$INIT_IN_IMAGE" ]] || fail "$1: calimero-init not rendered"
}

# The production image: no roots file, no block, nothing that could set the variable.
render locked-read-only
[[ -e "$work/locked-read-only/$ROOTS_IN_IMAGE" ]] && fail "locked-read-only must not ship the staging roots"
grep -qE 'MEROD_TLS_EXTRA_ROOTS|le-staging-roots|tls-extra-roots' "$work/locked-read-only/$INIT_IN_IMAGE" \
  && fail "locked-read-only calimero-init must not mention extra TLS roots"

# run INIT HELP: the rendered extra-roots block of INIT, with a merod whose
# `run --help` prints HELP. Prints the env file, then the log.
run() {
  local init="$1" help="$2" dir block code
  block="$(sed -n '/^# --- Extra TLS roots/,/^# --- merod 1.0: storage key/p' "$init" | sed '$d')"
  [[ -n "$block" ]] || fail "no extra TLS roots block in $init"
  dir="$(mktemp -d "$work/run.XXXX")"
  mkdir -p "$dir/bin"
  printf '#!/usr/bin/env bash\necho %q\n' "$help" >"$dir/bin/merod"
  chmod +x "$dir/bin/merod"
  : >"$dir/merod.env"
  cp "$ROOTS" "$dir/roots.pem"
  code="${block//\/etc\/calimero\/merod.env/$dir/merod.env}"
  code="${code//\/usr\/local\/lib\/calimero\/le-staging-roots.crt/$dir/roots.pem}"
  (
    BIN_DIR="$dir/bin"
    log() { echo "LOG: $*"; }
    env_file_value() { printf '%s' "$1"; }
    eval "$code"
  ) >"$dir/log"
  cat "$dir/merod.env" "$dir/log"
}

# The debug images: the bundle, byte for byte, and merod pointed at it.
with_flag="--tls-extra-roots <TLS_EXTRA_ROOTS>"
for profile in debug debug-read-only; do
  render "$profile"
  cmp -s "$ROOTS" "$work/$profile/$ROOTS_IN_IMAGE" || fail "$profile must ship le-staging-roots.crt unchanged"
  init="$work/$profile/$INIT_IN_IMAGE"
  grep -q 'get_meta tls-extra-roots' "$init" && fail "$profile: the roots must not depend on instance metadata"
  # merod.env is written (truncated) before the block appends to it, every boot.
  env_write=$(grep -nF '} > /etc/calimero/merod.env' "$init" | head -1 | cut -d: -f1)
  start=$(grep -nF '# --- Extra TLS roots' "$init" | head -1 | cut -d: -f1)
  (( env_write < start )) || fail "$profile: merod.env must be written before the extra roots block appends to it"

  out="$(run "$init" "$with_flag")"
  grep -qE '^MEROD_TLS_EXTRA_ROOTS=".*/roots\.pem"$' <<<"$out" \
    || fail "$profile with a merod that has the flag must set MEROD_TLS_EXTRA_ROOTS: $out"

  out="$(run "$init" "--recovery-dir <RECOVERY_DIR>")"
  grep -q MEROD_TLS_EXTRA_ROOTS <<<"$out" && fail "$profile: a merod without the flag must not get the variable: $out"
  grep -qF 'this merod has no --tls-extra-roots' <<<"$out" \
    || fail "$profile: a merod without the flag must be logged: $out"
done

echo "OK: debug images ship the Let's Encrypt staging roots and point merod at them; locked-read-only has neither"
