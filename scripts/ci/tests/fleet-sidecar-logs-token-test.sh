#!/usr/bin/env bash
# The observability bearer token arrives from mdma; it is never in the image.
#
# The node image is an artifact whose distribution is not fully controlled, so
# anything baked into it should be assumed readable. The image therefore carries
# the code to ASK for a credential, and mdma releases one only to a peer holding
# a verified attestation. Secret Manager is not an alternative here: mdma creates
# these instances with no service account, so there is no cloud identity for
# `gcloud` or the metadata server's token endpoint to use.
#
# What fails quietly without this test:
#   * reporting the TOKEN rather than its fingerprint, sending a secret back up
#     the wire on every one-second poll;
#   * hashing a file that does not exist and reporting garbage, so mdma re-sends
#     the token forever;
#   * `install_logs_token` printing to stdout -- the poll's stdout IS the
#     assignments payload, and corrupting it drives the LEAVE path, which purges
#     keys;
#   * storing the token but silently never starting vector when no endpoint is
#     configured;
#   * rotating the token into vector and leaving vmagent holding the superseded
#     one, so metrics start being rejected at the sink while logs keep flowing
#     and the node is half-authenticated with nothing to say so.
#
# Usage: scripts/ci/tests/fleet-sidecar-logs-token-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT
export SB
mkdir -p "${SB}/bin" "${SB}/vector" "${SB}/vmagent"

sed -e 's@{{ fleet_mdma_url }}@https://mdma.test@' \
    -e "s@{{ fleet_auth_token | default('') }}@@" \
    -e "s@/var/log/fleet-sidecar.log@${SB}/fleet.log@" \
    -e "s@/var/lib/calimero/@${SB}/@g" \
    -e "s@/mnt/data/tls@${SB}/tls@g" \
    -e "s@/etc/vector@${SB}/vector@g" \
    -e "s@/etc/vmagent@${SB}/vmagent@g" \
    "${TEMPLATE}" > "${SB}/rendered.sh"
sed -n '1,/^# --- Main loop ---$/p' "${SB}/rendered.sh" | sed '$d' > "${SB}/functions.sh"

# Metadata stub: each endpoint answers only once its fixture file exists.
cat > "${SB}/bin/curl" <<'STUB'
#!/usr/bin/env bash
url=""
for a in "$@"; do [[ "${a}" == http* ]] && url="${a}"; done
case "${url}" in
  *metadata.google.internal*logs-endpoint*)
    [[ -f "${SB}/endpoint" ]] || exit 1
    cat "${SB}/endpoint"; exit 0 ;;
  *metadata.google.internal*metrics-endpoint*)
    [[ -f "${SB}/metrics_endpoint" ]] || exit 1
    cat "${SB}/metrics_endpoint"; exit 0 ;;
  *metadata.google.internal*) exit 1 ;;
esac
exit 1
STUB
chmod +x "${SB}/bin/curl"

# configure_vector.sh / systemctl stubs record that they ran.
cat > "${SB}/vector/configure_vector.sh" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "${SB}/configured"
exit 0
STUB
chmod +x "${SB}/vector/configure_vector.sh"
: > "${SB}/vector/vector_partial.yaml"

cat > "${SB}/vmagent/configure_vmagent.sh" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "${SB}/vmagent_configured"
exit 0
STUB
chmod +x "${SB}/vmagent/configure_vmagent.sh"
: > "${SB}/vmagent/scrape_config.yml"

cat > "${SB}/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "${SB}/systemctl"
exit 0
STUB
chmod +x "${SB}/bin/systemctl"
PATH="${SB}/bin:${PATH}"
export PATH

# shellcheck source=/dev/null
source "${SB}/functions.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }

TOKEN="s3cr3t-victoria-bearer-token"
WANT_FP="$(printf '%s' "$TOKEN" | sha256sum | awk '{print $1}')"

# --- nothing installed -----------------------------------------------------
[[ -z "$(cached_logs_token_fp)" ]] || fail "a node with no token must report an empty fingerprint"

# --- delivery with no endpoint: store, do not start ------------------------
install_logs_token "$TOKEN" >"${SB}/stdout" 2>/dev/null
[[ ! -s "${SB}/stdout" ]] || fail "install_logs_token must print nothing to stdout"
[[ -s "${SB}/vector/provided_token" ]] || fail "the token must be stored even with no endpoint"
[[ ! -f "${SB}/configured" ]] || fail "vector must not be configured with no endpoint"
[[ ! -f "${SB}/vmagent_configured" ]] || fail "vmagent must not be configured with no endpoint"
grep -q "no logs-endpoint" "${SB}/fleet.log" || fail "a missing endpoint must say so in the log"
grep -q "No metrics-endpoint" "${SB}/fleet.log" || fail "a missing metrics endpoint must say so in the log"

perms=$(stat -c %a "${SB}/vector/provided_token")
[[ "$perms" == "600" ]] || fail "the token file must be 0600, got ${perms}"

# --- the fingerprint is of the TOKEN, and is not the token -----------------
got_fp="$(cached_logs_token_fp)"
[[ "$got_fp" == "$WANT_FP" ]] || fail "fingerprint mismatch: ${got_fp} != ${WANT_FP}"
[[ "$got_fp" != "$TOKEN" ]] || fail "the token itself must never be reported"
grep -q "$TOKEN" <<<"$got_fp" && fail "the fingerprint must not contain the token"

# --- delivery with an endpoint: configure and restart ----------------------
echo "https://victoria-lb.test/insert/elasticsearch" > "${SB}/endpoint"
install_logs_token "$TOKEN" >/dev/null 2>/dev/null
grep -q "provided" "${SB}/configured" \
  || fail "vector must be configured with the 'provided' secret provider"
grep -q "victoria-lb.test" "${SB}/configured" \
  || fail "vector must be configured against the metadata endpoint"
grep -q "restart vector" "${SB}/systemctl" || fail "vector must be restarted after install"

# --- metrics ride the same credential --------------------------------------
#
# vector and vmagent present the SAME bearer token to the SAME vmauth front
# end. A rotation that reconfigured only vector would leave vmagent holding the
# superseded one, and every sample would be rejected at the sink -- silently,
# on a node with no shell to notice it from.
echo "https://victoria-lb.test/api/v1/write" > "${SB}/metrics_endpoint"
: > "${SB}/vmagent_configured"
install_logs_token "$TOKEN" >"${SB}/stdout" 2>/dev/null
[[ ! -s "${SB}/stdout" ]] || fail "install_logs_token must print nothing to stdout"
grep -q "provided" "${SB}/vmagent_configured" \
  || fail "vmagent must be configured with the 'provided' secret provider"
grep -q "victoria-lb.test/api/v1/write" "${SB}/vmagent_configured" \
  || fail "vmagent must be configured against the metrics metadata endpoint"
grep -q "${SB}/vector/provided_token" "${SB}/vmagent_configured" \
  || fail "vmagent must read the SAME token file vector does, or rotation desynchronises them"

# --- rotation --------------------------------------------------------------
NEW="a-rotated-token"
: > "${SB}/configured"
: > "${SB}/vmagent_configured"
install_logs_token "$NEW" >/dev/null 2>/dev/null
[[ "$(cat "${SB}/vector/provided_token")" == "$NEW" ]] || fail "a rotated token must replace the old one"
[[ "$(cached_logs_token_fp)" != "$WANT_FP" ]] || fail "the reported fingerprint must follow rotation"
[[ -s "${SB}/configured" ]] || fail "a rotation must reconfigure vector"
[[ -s "${SB}/vmagent_configured" ]] || fail "a rotation must reconfigure vmagent too"

# --- the token is never briefly world-readable -----------------------------
#
# `chmod 600` AFTER the write closes the window; it does not prevent it. The
# unit sets no `UMask=`, so systemd's default 0022 would create the temp file
# 0644 and the secret would sit world-readable on disk until the chmod landed.
#
# Shadowing `chmod` observes the mode AS CREATED, which is the only moment that
# matters and the one a `stat` of the final file cannot see.
observed_create_mode() {
  local target="$1" token="$2"
  rm -f "${SB}/created_mode"
  # shellcheck disable=SC2317  # invoked indirectly: this shadows the builtin
  chmod() {
    # $1 is the mode, $2 the path -- record what the file looked like before
    # this call tightened it, then do the real thing.
    [[ -e "${2:-}" ]] && stat -c %a "$2" >> "${SB}/created_mode"
    command chmod "$@"
  }
  ( umask 022; "$target" "$token" ) >/dev/null 2>/dev/null
  unset -f chmod
  cat "${SB}/created_mode" 2>/dev/null || echo "MISSING"
}

mode="$(observed_create_mode install_logs_token "umask-probe-logs-token")"
[[ "$mode" == "600" ]]   || fail "the logs token was created ${mode}, not 600: world-readable until chmod"

mode="$(observed_create_mode save_fleet_token "umask-probe-fleet-token")"
[[ "$mode" == "600" ]]   || fail "the fleet token was created ${mode}, not 600: world-readable until chmod"

# Restore the token the rotation tests left in place, so ordering stays free.
install_logs_token "$NEW" >/dev/null 2>/dev/null

# --- an empty delivery is a no-op, not a wipe ------------------------------
install_logs_token "" >/dev/null 2>/dev/null
[[ "$(cat "${SB}/vector/provided_token")" == "$NEW" ]] \
  || fail "an empty delivery must not erase a good token"

echo "PASS: fleet sidecar observability token"
