#!/usr/bin/env bash
# Every secret a node writes to disk must be CREATED with a restrictive umask,
# never created loose and tightened afterwards.
#
# `chmod 600` after the write closes the window; it does not prevent it. None of
# these units set `UMask=`, so systemd's default 0022 applies and the file is
# created 0644 -- the secret sits world-readable until the chmod lands.
#
# The sidecar's two writes are covered behaviourally by
# fleet-sidecar-logs-token-test.sh, which shadows `chmod` to observe the mode AS
# CREATED. calimero-init cannot be covered that way: it is a linear boot script,
# not a set of sourceable functions, so there is nothing to call. It is also the
# script that writes the observability token on EVERY node at boot, which makes
# it the one place this matters most.
#
# Hence a static check across BOTH templates. It is deliberately narrow: it
# looks only at redirections into a variable whose name says it holds a token,
# and requires the redirection to sit inside a `umask` subshell. That is the
# exact shape of the bug and the exact shape of the fix, so it cannot drift into
# a general-purpose shell linter that everyone learns to ignore.
#
# Usage: scripts/ci/tests/secret-file-umask-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATES=(
  "${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/calimero-init.sh.j2"
  "${REPO_ROOT}/mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"
)

fail() { echo "FAIL: $*" >&2; exit 1; }

# A line that redirects into a *_TOKEN*-ish variable, e.g.
#   printf '%s' "$tok" > "$OBS_TOKEN_TMP"
#   ( umask 077; printf '%s' "$token" > "$tmp" )
# The second form names its target `$tmp`, so match on the WRITE of a secret
# rather than on the variable name alone: any `printf` redirecting to a file,
# inside a function or block that handles a token.
WRITES_RE='printf[^>]*>[[:space:]]*"?\$'

checked=0
for tpl in "${TEMPLATES[@]}"; do
  [[ -r "$tpl" ]] || fail "cannot read ${tpl}"
  while IFS= read -r line; do
    # Only redirections that land in a path built from a token variable.
    case "$line" in
      *TOKEN*|*token*) : ;;
      *) continue ;;
    esac
    # Certificates and CSRs are public material and deliberately not restricted.
    case "$line" in
      *csr*|*CSR*|*cert*|*CERT*) continue ;;
    esac
    checked=$((checked + 1))
    case "$line" in
      *"umask 077"*) : ;;
      *) fail "$(basename "$tpl"): a token is written without a restrictive umask,
       so it exists world-readable until a later chmod:
         ${line#"${line%%[![:space:]]*}"}" ;;
    esac
  done < <(grep -E "$WRITES_RE" "$tpl" || true)
done

[[ "$checked" -ge 3 ]] || fail "expected at least 3 token writes across the templates, saw ${checked};
       the matcher has probably stopped matching -- check it before trusting a pass"

echo "PASS: all ${checked} token writes are created under umask 077"
