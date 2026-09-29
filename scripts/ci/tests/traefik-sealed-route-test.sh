#!/usr/bin/env bash
#
# The sealed-transport router may exist only where it cannot become a bypass.
#
# `node-sealed` exempts `POST /sealed/v2` and `/sealed/v2/handshake` from
# `auth-node`, because forwardAuth cannot see the route a sealed request names:
# it is inside the envelope. That is safe only because merod, in proxy auth
# mode, lets an opened request reach nothing but what it serves without a
# credential. merod enforces that from 0.11.0-rc.52; an older merod routes an
# opened request anywhere, so this router in front of it would reach every
# route `auth-node` guards, DELETEs included.
#
# So, while the router exists:
#   * it sits inside the relay-only `fleet_delegated_access` block, since the
#     delegated routes (`/intents`, `/context-intents`, `/governance-intents`)
#     are the only writes a sealed request can do on these nodes;
#   * it matches the two envelope paths exactly, POST and OPTIONS only, never a
#     prefix;
#   * it is rate limited and never behind `auth-node` (which would make it
#     unreachable, not safe);
#   * `mero-tee/versions.json` pins a merod of at least 0.11.0-rc.52.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="$ROOT/mero-tee/ansible/roles/mero-traefik/templates/traefik-routing.yml.j2"
VERSIONS="$ROOT/mero-tee/versions.json"

for f in "$TEMPLATE" "$VERSIONS"; do
  [ -f "$f" ] || { echo "FATAL: $f not found"; exit 1; }
done

python3 - "$TEMPLATE" "$VERSIONS" <<'PY'
import json
import re
import sys

template_path, versions_path = sys.argv[1:3]
text = open(template_path, encoding="utf-8").read()
# Comments explain the router and must not count as it.
text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
lines = [re.sub(r"\s+#.*$", "", l) if not l.lstrip().startswith("#") else "" for l in text.splitlines()]

start = next((i for i, l in enumerate(lines) if re.match(r"^\s*node-sealed:\s*$", l)), None)
if start is None:
    print("OK: no sealed-transport router; nothing to check")
    sys.exit(0)

failures = []

# Its body: the lines indented deeper than its name, up to the next sibling.
indent = len(lines[start]) - len(lines[start].lstrip())
body = []
for l in lines[start + 1:]:
    if l.strip() and len(l) - len(l.lstrip()) <= indent:
        break
    body.append(l)
body_text = "\n".join(body)

# Inside the relay-only block: the nearest enclosing `{% if %}` above it must be
# `fleet_delegated_access`, and it must not have closed before the router.
depth_stack = []
for l in lines[:start]:
    opened = re.match(r"^\s*\{%\s*if\s+(.*?)\s*%\}\s*$", l)
    if opened:
        depth_stack.append(opened.group(1))
    elif re.match(r"^\s*\{%\s*endif\s*%\}\s*$", l):
        if depth_stack:
            depth_stack.pop()
if not depth_stack or "fleet_delegated_access" not in depth_stack[-1]:
    failures.append("node-sealed must sit inside the `{% if fleet_delegated_access %}` block")

rule = re.search(r'rule:\s*"(.*)"', body_text)
if not rule:
    failures.append("node-sealed has no rule")
else:
    rule = rule.group(1)
    paths = set(re.findall(r"Path\(`([^`]*)`\)", rule))
    if paths != {"/sealed/v2", "/sealed/v2/handshake"}:
        failures.append(f"node-sealed must match exactly /sealed/v2 and /sealed/v2/handshake, got {sorted(paths)}")
    if re.search(r"PathPrefix|PathRegexp|HostRegexp", rule):
        failures.append("node-sealed must match exact paths, never a prefix or pattern")
    methods = set(re.findall(r"Method\(`([^`]*)`\)", rule))
    if methods != {"POST", "OPTIONS"}:
        failures.append(f"node-sealed must allow POST and OPTIONS only, got {sorted(methods)}")

middlewares = re.findall(r"^\s*-\s*([\w-]+)\s*$", body_text, flags=re.M)
if "auth-node" in middlewares:
    failures.append("node-sealed must not be behind auth-node: forwardAuth cannot see inside an envelope")
if not any(m.startswith("rate-limit") for m in middlewares):
    failures.append("node-sealed must be rate limited")

def parse(version):
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?", version)
    if not m:
        return None
    major, minor, patch, rc = m.groups()
    # A release outranks every release candidate of the same version.
    return (int(major), int(minor), int(patch), int(rc) if rc is not None else float("inf"))

merod = json.load(open(versions_path, encoding="utf-8")).get("merodVersion", "")
floor = "0.11.0-rc.52"
parsed = parse(merod)
if parsed is None:
    failures.append(f"merodVersion {merod!r} is not a version this check can compare")
elif parsed < parse(floor):
    failures.append(
        f"merodVersion {merod} predates {floor}, whose sealed layer refuses routes a proxy "
        "guards; the node-sealed router in front of it would bypass auth-node"
    )

if failures:
    for f in failures:
        print(f"FAIL: {f}")
    sys.exit(1)
print(f"OK: node-sealed is relay-only, exact, rate limited, unguarded by design, and merod {merod} enforces the boundary")
PY
