#!/usr/bin/env bash
# Behavioural test: `mero-auth-start` turns device-key login on exactly when it
# should, and the config it hands mero-auth is valid TOML.
#
# mero-auth's `account_proof` provider refuses to start without this node's
# device signing key, and a mero-auth that does not start takes every
# forwardAuth on the node down with it. So the wrapper must:
#
#   * on a relay image with a recorded 64-hex key, run mero-auth on a copy of
#     the baked config with the `providers` and `account_proof` tables added,
#     naming that key and accepting any audience;
#   * with no key, a malformed key, or on a non-relay image, run it on the
#     baked config untouched, which enables no provider.
#
# It also checks the baked config itself declares neither table: appending one
# the file already has is a TOML error, and mero-auth would not start.
#
# Usage: scripts/ci/tests/mero-auth-device-login-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ROLE="${REPO_ROOT}/mero-tee/ansible/roles/merotee"
WRAPPER="${ROLE}/files/mero-auth-start.sh"
BAKED_SRC="${ROLE}/files/mero-auth-config.toml"

SB="$(mktemp -d)"
trap 'rm -rf "${SB}"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# A stand-in mero-auth: records the config it was started with.
cat > "${SB}/mero-auth" <<STUB
#!/usr/bin/env bash
[[ "\$1" == "--config" ]] || exit 64
printf '%s' "\$2" > "${SB}/started-with"
STUB
chmod +x "${SB}/mero-auth"
cp "${BAKED_SRC}" "${SB}/auth.toml"

# `relay` renders the wrapper with a marker that exists, `plain` with one that
# does not: the only difference between a relay image and any other.
touch "${SB}/device-key-login"
render() {
  local name="$1" marker="$2"
  sed -e "s@/etc/calimero/device-key-login@${marker}@" \
      -e "s@/etc/calimero/auth.toml@${SB}/auth.toml@" \
      -e "s@/mnt/data/fleet/login-node-key@${SB}/login-node-key@" \
      -e "s@/run/calimero/auth.toml@${SB}/run/auth.toml@" \
      "${WRAPPER}" > "${SB}/start-${name}.sh"
  chmod +x "${SB}/start-${name}.sh"
}
render relay "${SB}/device-key-login"
render plain "${SB}/no-such-marker"

start() {
  rm -f "${SB}/started-with" "${SB}/run/auth.toml"
  MERO_AUTH="${SB}/mero-auth" "${SB}/start-$1.sh" >/dev/null 2>&1 || fail "wrapper exited non-zero ($1)"
  cat "${SB}/started-with"
}

KEY="$(printf 'ab%.0s' {1..32})"

# --- the baked config declares neither table --------------------------------
python3 - "${SB}/auth.toml" <<'PY' || fail "the baked config must parse and declare no providers / account_proof table"
import sys, tomllib
cfg = tomllib.load(open(sys.argv[1], "rb"))
assert "providers" not in cfg, cfg.get("providers")
assert "account_proof" not in cfg, cfg.get("account_proof")
assert cfg["listen_addr"] == "127.0.0.1:3001"
PY

# --- no key yet: baked config, no provider ----------------------------------
[[ "$(start relay)" == "${SB}/auth.toml" ]] || fail "with no key the baked config must be used"

# --- a malformed key: baked config ------------------------------------------
echo "not-a-key" > "${SB}/login-node-key"
[[ "$(start relay)" == "${SB}/auth.toml" ]] || fail "a malformed key must not enable the provider"
echo "${KEY^^}" > "${SB}/login-node-key"
[[ "$(start relay)" == "${SB}/auth.toml" ]] || fail "only lowercase hex is a key merod publishes"

# --- a recorded key on a relay: provider on, valid TOML ---------------------
printf '%s\n' "${KEY}" > "${SB}/login-node-key"
[[ "$(start relay)" == "${SB}/run/auth.toml" ]] || fail "a recorded key must start mero-auth on the generated config"
python3 - "${SB}/run/auth.toml" "${KEY}" <<'PY' || fail "the generated config is not what mero-auth needs"
import sys, tomllib
cfg = tomllib.load(open(sys.argv[1], "rb"))
assert cfg["providers"] == {"account_proof": True}, cfg["providers"]
assert cfg["account_proof"]["node_key"] == sys.argv[2], cfg["account_proof"]
assert cfg["account_proof"]["allowed_audiences"] == [], cfg["account_proof"]
# Everything baked is kept: the generated file only adds.
assert cfg["listen_addr"] == "127.0.0.1:3001"
assert cfg["storage"]["path"] == "/mnt/data/calimero/default/auth_db"
PY

# --- a non-relay image never enables it --------------------------------------
[[ "$(start plain)" == "${SB}/auth.toml" ]] || fail "a non-relay image must ignore a recorded key"

echo "OK: mero-auth-start enables device-key login only on a relay with a recorded key"
