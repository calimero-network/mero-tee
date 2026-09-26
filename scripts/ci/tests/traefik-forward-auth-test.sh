#!/usr/bin/env bash
#
# The node's forwardAuth must not trust client-supplied X-Forwarded-* headers.
#
# mero-auth's `/auth/validate` decides a scoped token against the route in
# `X-Forwarded-Uri` / `X-Forwarded-Method`. With `trustForwardHeader: true`,
# Traefik forwards whatever the CLIENT sent in those headers, so a token scoped
# to route A reaches route B by claiming `X-Forwarded-Uri: A` (mero-tee#339).
# With `false`, Traefik overwrites them from the request it is routing.
#
# The setting is required EXPLICITLY on every forwardAuth, not left to Traefik's
# default: a missing key reads the same as a deliberate one in review, and a
# default is the thing a version bump is allowed to change.
#
# The entrypoints are checked too. `forwardedHeaders.insecure` or `trustedIPs`
# there would have Traefik keep a client's X-Forwarded-* before any middleware
# runs; nothing sits in front of this ingress that could earn that trust.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ROLE="$ROOT/mero-tee/ansible/roles/mero-traefik"
TEMPLATE="$ROLE/templates/traefik-routing.yml.j2"
STATIC="$ROLE/files/traefik-config.yml"

for f in "$TEMPLATE" "$STATIC"; do
  [ -f "$f" ] || { echo "FATAL: $f not found"; exit 1; }
done

python3 - "$TEMPLATE" "$STATIC" <<'PY'
import re
import sys

def uncommented(path):
    text = open(path, encoding="utf-8").read()
    # Every Jinja branch renders on some image, so directives are stripped
    # rather than evaluated; comments explain the setting and must not count
    # as it.
    text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
    text = re.sub(r"\{%.*?%\}", "", text, flags=re.S)
    return "\n".join(re.sub(r"\s*#.*$", "", line) for line in text.splitlines())

routing = uncommented(sys.argv[1])
static = uncommented(sys.argv[2])
failures = []

# Each `forwardAuth:` block runs until the next line indented no deeper.
blocks = []
lines = routing.splitlines()
for i, line in enumerate(lines):
    m = re.match(r"^(\s*)forwardAuth:\s*$", line)
    if not m:
        continue
    indent = len(m.group(1))
    body = []
    for nxt in lines[i + 1:]:
        if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= indent:
            break
        body.append(nxt)
    # Named by the middleware that owns it: line numbers here are of the
    # stripped text, not the template.
    owner = next((re.match(r"\s*([A-Za-z0-9-]+):", l).group(1)
                  for l in reversed(lines[:i]) if re.match(r"\s*[A-Za-z0-9-]+:\s*$", l)), "?")
    blocks.append((owner, "\n".join(body)))

if not blocks:
    failures.append("no forwardAuth middleware found; did auth-node move?")

for owner, body in blocks:
    values = re.findall(r"^\s*trustForwardHeader:\s*(\S+)\s*$", body, flags=re.M)
    if values != ["false"]:
        failures.append(
            f"{owner} forwardAuth: trustForwardHeader is {values or 'unset'}, "
            f"want exactly one explicit `false`"
        )

if re.search(r"^\s*forwardedHeaders:", static, flags=re.M):
    failures.append(
        "traefik-config.yml sets entrypoint forwardedHeaders; the node ingress "
        "has no trusted proxy in front of it"
    )

if failures:
    for line in failures:
        print(f"FAIL {line}")
    sys.exit(1)

for owner, _ in blocks:
    print(f"ok   {owner} forwardAuth: trustForwardHeader false")
print("ok   entrypoints trust no forwarded headers")
PY
