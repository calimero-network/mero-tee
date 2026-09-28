#!/usr/bin/env bash
# Start mero-auth, with device-key login once this node can name itself.
#
# `/etc/calimero/auth.toml` is baked into the image (and so measured) and
# enables no provider. On a relay image — one the build gave MARKER, from
# `fleet_delegated_access` — this adds the `account_proof` provider, device-key
# login, as soon as the fleet sidecar has recorded this node's device signing
# key in KEY_FILE.
#
# Why the key is not baked: it is minted inside merod's store on the data disk,
# per node, so no image can carry it. Why the provider waits for it: it refuses
# to start without one, because the key is what every login statement names
# and checking it is what stops a statement signed for another node being
# replayed here. Enabling it with no key would take mero-auth — and with it
# every forwardAuth on this node — down.
#
# The generated file lives in /run (RAM) and is rebuilt on every start, so the
# only persistent input is the 64-hex key, which is validated before use.
set -euo pipefail

BAKED="/etc/calimero/auth.toml"
KEY_FILE="/mnt/data/fleet/login-node-key"
RUNTIME="/run/calimero/auth.toml"
MARKER="/etc/calimero/device-key-login"
MERO_AUTH="${MERO_AUTH:-/usr/local/bin/mero-auth}"

config="$BAKED"

if [[ -e "$MARKER" ]]; then
  key=""
  if [[ -r "$KEY_FILE" ]]; then
    key=$(tr -d '[:space:]' < "$KEY_FILE")
  fi

  if [[ "$key" =~ ^[0-9a-f]{64}$ ]]; then
    mkdir -p "$(dirname "$RUNTIME")"
    tmp=$(mktemp "${RUNTIME}.XXXXXX")
    # `[providers]` and `[account_proof]` are appended, so the baked file must
    # not declare either table: TOML refuses a table declared twice.
    # scripts/ci/tests/mero-auth-device-login-test.sh holds it to that.
    #
    # `allowed_audiences = []` accepts a session for any client origin. The
    # session only lets a caller ASK: every read re-checks membership, every
    # write needs the member's own warrant, and the listings are scoped to the
    # caller's groups — which merod sees through `server.proxy_identity`.
    {
      cat "$BAKED"
      printf '\n[providers]\naccount_proof = true\n\n[account_proof]\nnode_key = "%s"\nallowed_audiences = []\n' "$key"
    } > "$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$RUNTIME"
    config="$RUNTIME"
    echo "mero-auth-start: device-key login enabled for node key $key"
  elif [[ -n "$key" ]]; then
    echo "mero-auth-start: WARN: $KEY_FILE does not hold a 64-hex key; starting without device-key login" >&2
  else
    echo "mero-auth-start: no node key recorded yet; device-key login stays off until the fleet sidecar records one"
  fi
fi

exec "$MERO_AUTH" --config "$config"
