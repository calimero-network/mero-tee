#!/usr/bin/env bash
# Extra TLS roots: a staging node trusts the Let's Encrypt staging roots for
# HTTPS to its peers (merod --tls-extra-roots), and nothing else ever does.
#
# What fails quietly without this test:
#   * a value other than exactly `le-staging` (or a path) makes merod trust
#     roots the image did not ship;
#   * a production VM (no metadata) gets MEROD_TLS_EXTRA_ROOTS;
#   * a merod without the flag is given the variable and ignores it, so the
#     node cannot join and nothing says why;
#   * the shipped bundle drifts from the four published staging roots.
#
# The block is cut out of calimero-init and run with get_meta, merod and the
# env file stubbed.
#
# Usage: scripts/ci/tests/tls-extra-roots-test.sh
# The stubs are used by the block run through eval.
# shellcheck disable=SC2034,SC2329
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/calimero-init.sh.j2"
ROOTS="${REPO_ROOT}/mero-tee/ansible/roles/merotee/files/le-staging-roots.crt"
TASKS="${REPO_ROOT}/mero-tee/ansible/roles/merotee/tasks/main.yml"

fail() { echo "FAIL: $*" >&2; exit 1; }
[[ -r "$TEMPLATE" ]] || fail "cannot read ${TEMPLATE}"
body="$(cat "$TEMPLATE")"
start=$(grep -nF '# --- Extra TLS roots' <<<"$body" | head -1 | cut -d: -f1)
end=$(grep -nF '# --- merod 1.0: storage key' <<<"$body" | head -1 | cut -d: -f1)
[[ -n "$start" && -n "$end" ]] || fail "could not locate the extra TLS roots block"
block="$(sed -n "${start},$((end - 1))p" <<<"$body")"

# merod.env is written (truncated) before the block appends to it, every boot.
env_write=$(grep -nF '} > /etc/calimero/merod.env' <<<"$body" | head -1 | cut -d: -f1)
(( env_write < start )) || fail "merod.env must be written before the extra roots block appends to it"

# The image ships the bundle where the block reads it.
grep -qF 'dest: /usr/local/lib/calimero/le-staging-roots.crt' "$TASKS" \
  || fail "the role must install le-staging-roots.crt at /usr/local/lib/calimero/"
grep -qF 'LE_STAGING_ROOTS="/usr/local/lib/calimero/le-staging-roots.crt"' <<<"$block" \
  || fail "the block must read the bundle the role installs"

# The bundle is exactly the four published staging roots
# (https://letsencrypt.org/docs/staging-environment/).
expected="9B:2A:33:9F:E6:A3:E8:55:85:C4:CD:75:53:6C:B8:C1:CF:7C:D6:03:B9:A6:4B:EC:25:21:85:8A:E4:8D:A8:5D
B5:9B:FC:0B:A5:2D:AF:84:98:53:B7:32:4A:91:E8:2F:03:1D:B3:39:7F:35:64:41:57:35:2C:DE:63:84:B5:6C
E7:05:70:A9:89:F8:56:5A:AB:DF:7C:AE:27:AB:D1:62:18:72:D6:A3:F8:11:E3:FE:F2:7E:3D:BA:02:91:21:98
EF:11:5F:B5:9E:04:0F:F3:9D:15:FD:8F:3E:F5:40:63:C7:04:32:1D:83:CB:08:12:13:27:2F:77:D3:09:16:72"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
awk -v dir="$work" '/-----BEGIN CERTIFICATE-----/{n++; on=1} on{print >> (dir "/cert" n ".pem")} /-----END CERTIFICATE-----/{on=0}' "$ROOTS"
got="$(for c in "$work"/cert*.pem; do openssl x509 -in "$c" -noout -fingerprint -sha256 | cut -d= -f2; done | sort)"
[[ "$got" == "$expected" ]] || fail "le-staging-roots.crt is not the four Let's Encrypt staging roots:
$got"
rm -f "$work"/cert*.pem

# run META HELP: the block with metadata `tls-extra-roots` = META and a merod
# whose `run --help` prints HELP. Prints the env file, then the log.
run() {
  local meta="$1" help="$2" dir
  dir="$(mktemp -d "$work/run.XXXX")"
  mkdir -p "$dir/bin"
  printf '#!/usr/bin/env bash\necho %q\n' "$help" >"$dir/bin/merod"
  chmod +x "$dir/bin/merod"
  : >"$dir/merod.env"
  cp "$ROOTS" "$dir/roots.pem"
  local code="${block//\/etc\/calimero\/merod.env/$dir/merod.env}"
  code="${code//\/usr\/local\/lib\/calimero\/le-staging-roots.crt/$dir/roots.pem}"
  (
    BIN_DIR="$dir/bin"
    get_meta() { [[ "$1" == tls-extra-roots ]] && printf '%s' "$meta"; return 0; }
    log() { echo "LOG: $*"; }
    env_file_value() { printf '%s' "$1"; }
    eval "$code"
  ) >"$dir/log"
  cat "$dir/merod.env" "$dir/log"
}

with_flag="--tls-extra-roots <TLS_EXTRA_ROOTS>"
out="$(run le-staging "$with_flag")"
grep -qE '^MEROD_TLS_EXTRA_ROOTS=".*/roots\.pem"$' <<<"$out" \
  || fail "le-staging with a merod that has the flag must set MEROD_TLS_EXTRA_ROOTS: $out"

out="$(run "" "$with_flag")"
grep -q MEROD_TLS_EXTRA_ROOTS <<<"$out" && fail "no metadata (production) must not set extra roots: $out"
grep -q WARN <<<"$out" && fail "no metadata must log nothing: $out"

for bad in le-staging/../x /etc/ssl/certs/ca.pem LE-STAGING " le-staging" production true; do
  out="$(run "$bad" "$with_flag")"
  grep -q MEROD_TLS_EXTRA_ROOTS <<<"$out" && fail "metadata '$bad' must not set extra roots: $out"
  grep -qF 'WARN: ignoring instance metadata tls-extra-roots' <<<"$out" \
    || fail "metadata '$bad' must be logged as ignored: $out"
done

out="$(run le-staging "--recovery-dir <RECOVERY_DIR>")"
grep -q MEROD_TLS_EXTRA_ROOTS <<<"$out" && fail "a merod without the flag must not get the variable: $out"
grep -qF 'this merod has no --tls-extra-roots' <<<"$out" \
  || fail "a merod without the flag must be logged: $out"

echo "OK: only tls-extra-roots=le-staging adds the shipped Let's Encrypt staging roots, and only for a merod that takes them"
