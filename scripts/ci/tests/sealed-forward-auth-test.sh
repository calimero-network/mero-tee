#!/usr/bin/env bash
#
# Sealed requests on a relay are guarded by the same mero-auth traefik asks.
#
# calimero-init sets `server.sealed.forward_auth` so merod asks mero-auth about
# an opened sealed request, as traefik's `auth-node` does about a plain one.
# That holds only while:
#   * the origin is the one traefik's `auth-service` points at, so both paths
#     ask the same mero-auth;
#   * it is set only on relays (`fleet_delegated_access`), the images with the
#     `node-sealed` router;
#   * it never stops the boot: a node without it is the node from before;
#   * `mero-tee/versions.json` pins a merod that knows the key. An older one
#     refuses it, so every relay would silently stay unsealed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
INIT="$ROOT/mero-tee/ansible/roles/merotee/templates/calimero-init.sh.j2"
ROUTING="$ROOT/mero-tee/ansible/roles/mero-traefik/templates/traefik-routing.yml.j2"
VERSIONS="$ROOT/mero-tee/versions.json"

for f in "$INIT" "$ROUTING" "$VERSIONS"; do
  [ -f "$f" ] || { echo "FATAL: $f not found"; exit 1; }
done

python3 - "$INIT" "$ROUTING" "$VERSIONS" <<'PY'
import json
import re
import sys

init_path, routing_path, versions_path = sys.argv[1:4]
failures = []

# Comments explain the setting and must not count as it.
lines = [
    "" if l.lstrip().startswith("#") else l
    for l in open(init_path, encoding="utf-8").read().splitlines()
]

sets = [i for i, l in enumerate(lines) if "server.sealed.forward_auth=" in l]
if len(sets) != 1:
    failures.append(f"calimero-init must set server.sealed.forward_auth exactly once, found {len(sets)}")
else:
    at = sets[0]
    value = re.search(r"""'server\.sealed\.forward_auth="([^"]*)"'""", lines[at])
    if not value:
        failures.append("server.sealed.forward_auth must be written as a quoted TOML string")
        value = None
    else:
        value = value.group(1)

    # Inside the relay-only block: the nearest enclosing `{% if %}` above it.
    stack = []
    for l in lines[:at]:
        opened = re.match(r"^\s*\{%\s*if\s+(.*?)\s*%\}\s*$", l)
        if opened:
            stack.append(opened.group(1))
        elif re.match(r"^\s*\{%\s*(endif|else)\s*%\}\s*$", l):
            if stack:
                stack.pop()
            if re.match(r"^\s*\{%\s*else\s*%\}", l):
                stack.append("else")
    if not stack or "fleet_delegated_access" not in stack[-1]:
        failures.append("server.sealed.forward_auth must be set inside the `{% if fleet_delegated_access %}` block")

    # Non-fatal: the command's continuation ends in `|| log`, never `|| fatal`.
    tail = []
    for l in lines[at:at + 4]:
        tail.append(l)
        if not l.rstrip().endswith("\\"):
            break
    tail = "\n".join(tail)
    if "|| fatal" in tail or "|| log" not in tail:
        failures.append("a failure to set server.sealed.forward_auth must be logged, not fatal")

    # The same mero-auth traefik's auth-service uses.
    routing = open(routing_path, encoding="utf-8").read()
    service = re.search(r"^\s*auth-service:\s*\n(?:\s+.*\n)*?\s*-\s*url:\s*\"([^\"]+)\"", routing, flags=re.M)
    if not service:
        failures.append("traefik's auth-service url not found in routing.yml")
    elif value is not None and value != service.group(1):
        failures.append(
            f"server.sealed.forward_auth is {value!r} but traefik's auth-service is {service.group(1)!r}; "
            "sealed and plain requests would ask different auth services"
        )
    if value is not None and not re.fullmatch(r"http://127\.0\.0\.1:\d+", value):
        failures.append(f"server.sealed.forward_auth {value!r} is not a loopback http origin; merod refuses it")

def parse(version):
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?", version)
    if not m:
        return None
    major, minor, patch, rc = m.groups()
    # A release outranks every release candidate of the same version.
    return (int(major), int(minor), int(patch), int(rc) if rc is not None else float("inf"))

merod = json.load(open(versions_path, encoding="utf-8")).get("merodVersion", "")
floor = "0.11.0-rc.84"
parsed = parse(merod)
if parsed is None:
    failures.append(f"merodVersion {merod!r} is not a version this check can compare")
elif parsed < parse(floor):
    failures.append(
        f"merodVersion {merod} predates {floor}, the first merod with server.sealed.forward_auth; "
        "it refuses the key and every relay stays unsealed"
    )

if failures:
    for f in failures:
        print(f"FAIL: {f}")
    sys.exit(1)
print(f"OK: relays guard sealed requests with traefik's own mero-auth, non-fatally, on merod {merod}")
PY
