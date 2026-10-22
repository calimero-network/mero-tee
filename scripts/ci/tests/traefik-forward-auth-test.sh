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

# --- app hosts ---------------------------------------------------------------
# `<52-char base32 app id>.<base domain>` serves an installed app. merod checks
# the exact base domain; these routers only have to pick the right backend and
# guard, host-agnostically (no per-node value may enter a measured file).
routers = {}
in_routers = False
current = None
for line in lines:
    if re.match(r"^  routers:\s*$", line):
        in_routers = True
        continue
    if in_routers and re.match(r"^  \S", line):
        break
    if not in_routers:
        continue
    m = re.match(r"^    ([A-Za-z0-9-]+):\s*$", line)
    if m:
        current = routers[m.group(1)] = {"mw": [], "rule": "", "service": "", "priority": 0}
        continue
    if current is None:
        continue
    for key in ("rule", "service"):
        m = re.match(rf"^\s+{key}:\s*['\"]?(.*?)['\"]?\s*$", line)
        if m:
            current[key] = m.group(1)
    m = re.match(r"^\s+priority:\s*(\d+)\s*$", line)
    if m:
        current["priority"] = int(m.group(1))
    m = re.match(r"^\s+-\s*([a-z-]+)\s*$", line)
    if m:
        current["mw"].append(m.group(1))

APP_HOST = r"HostRegexp(`^[a-z2-7]{52}\..+$`)"
app = {n: r for n, r in routers.items() if APP_HOST in r["rule"]}
if len(app) != 4:
    failures.append(f"expected 4 app-host routers, found {sorted(app)}")
for name, r in app.items():
    if not r["rule"].startswith(APP_HOST):
        failures.append(f"{name}: rule does not lead with the app-host matcher")
    if re.search(r"Host\(", r["rule"]):
        failures.append(f"{name}: rule names a host; no per-node value may be baked in")
    if "rate-limit" not in r["mw"]:
        failures.append(f"{name}: no rate-limit")
    if "cors" in r["mw"]:
        failures.append(f"{name}: app hosts must not carry cors")

def find(pred):
    return [(n, r) for n, r in app.items() if pred(r["rule"])]

api = find(lambda rule: all(p in rule for p in ("/jsonrpc", "/ws", "/sse", "/admin-api/")))
files = find(lambda rule: "PathPrefix" not in rule and "Path(" not in rule)
refresh = find(lambda rule: "/auth/refresh" in rule and "/auth/validate" in rule)
login = find(lambda rule: "/auth/login" in rule)
for what, found in (("api", api), ("files", files), ("refresh/validate", refresh), ("login", login)):
    if len(found) != 1:
        failures.append(f"expected one app-host {what} router, found {[n for n, _ in found]}")
if len(api) == 1 and len(files) == 1 and len(refresh) == 1 and len(login) == 1:
    api, files, refresh, login = api[0][1], files[0][1], refresh[0][1], login[0][1]
    if "auth-node" not in api["mw"]:
        failures.append("app-host api router has no auth-node")
    if api["service"] != "node-core":
        failures.append("app-host api router does not go to merod")
    if "auth-node" in files["mw"]:
        failures.append("app-host file router has auth-node; app files are public")
    if files["service"] != "node-core":
        failures.append("app-host file router does not go to merod")
    if refresh["service"] != "auth-service":
        failures.append("app-host /auth/refresh and /auth/validate do not go to mero-auth")
    if login["service"] != "node-core":
        failures.append("app-host /auth/login does not go to merod")
    for what, r in (("api", api), ("refresh/validate", refresh), ("login", login)):
        if r["priority"] <= files["priority"]:
            failures.append(f"app-host {what} router does not outrank the file router")
    if files["priority"] <= 10:
        failures.append("app-host file router does not outrank node-api")

# A node's own host has no 52-char base32 first label, so none of the above applies to it.
rx = re.compile(r"^[a-z2-7]{52}\..+$")
if rx.match("relay-07.relay.calimero.network") or not rx.match("a" * 52 + ".relay.calimero.network"):
    failures.append("the app-host pattern does not separate app hosts from node hosts")

if failures:
    for line in failures:
        print(f"FAIL {line}")
    sys.exit(1)

for owner, _ in blocks:
    print(f"ok   {owner} forwardAuth: trustForwardHeader false")
print("ok   entrypoints trust no forwarded headers")
print("ok   app-host routers: api guarded, files public, no cors")
PY
