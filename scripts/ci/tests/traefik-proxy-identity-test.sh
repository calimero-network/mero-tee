#!/usr/bin/env bash
#
# A client must never be able to name the account merod scopes it as.
#
# On a relay, merod runs with `server.proxy_identity`: it takes a device-key
# session's account and device from the `X-Auth-Account` / `X-Auth-Device`
# headers and narrows listings, reads and subscriptions to that account's
# groups. merod cannot tell who wrote those headers, so Traefik has to make
# sure only mero-auth ever does:
#
#   * `auth-node` lists both in `authResponseHeaders`, so on a guarded route
#     Traefik replaces them with mero-auth's answer;
#   * `strip-proxy-identity` deletes both, and is attached to EVERY entrypoint,
#     so a route that skips `auth-node` (intents, admission, the sealed
#     envelope, the auth service) never carries a client's value;
#   * the middleware is defined outside any `{% if %}`, since the entrypoints
#     reference it on every image and a missing one fails every router;
#   * `mero-tee/versions.json` pins a merod that knows `server.proxy_identity`.
#     An older one ignores the key, and a relay with device-key login on would
#     answer every tenant's session node-wide.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ROLE="$ROOT/mero-tee/ansible/roles/mero-traefik"
TEMPLATE="$ROLE/templates/traefik-routing.yml.j2"
STATIC="$ROLE/files/traefik-config.yml"
VERSIONS="$ROOT/mero-tee/versions.json"

for f in "$TEMPLATE" "$STATIC" "$VERSIONS"; do
  [ -f "$f" ] || { echo "FATAL: $f not found"; exit 1; }
done

python3 - "$TEMPLATE" "$STATIC" "$VERSIONS" <<'PY'
import json
import re
import sys

template_path, static_path, versions_path = sys.argv[1:4]
HEADERS = ("X-Auth-Account", "X-Auth-Device")
failures = []

def strip_comments(text):
    text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
    return "\n".join(re.sub(r"\s+#.*$|^\s*#.*$", "", line) for line in text.splitlines())

def block(lines, start):
    """The lines under `lines[start]`, up to the next one indented no deeper."""
    indent = len(lines[start]) - len(lines[start].lstrip())
    body = []
    for line in lines[start + 1:]:
        if line.strip() and len(line) - len(line.lstrip()) <= indent:
            break
        body.append(line)
    return "\n".join(body)

raw_template = open(template_path, encoding="utf-8").read()
template = strip_comments(raw_template)
lines = template.splitlines()

# --- auth-node replaces both headers --------------------------------------
auth_node = [i for i, l in enumerate(lines) if re.match(r"^\s*auth-node:\s*$", l)]
if len(auth_node) != 1:
    failures.append(f"expected one auth-node middleware, found {len(auth_node)}")
else:
    body = block(lines, auth_node[0])
    listed = re.findall(r"^\s*-\s*(X-Auth-[A-Za-z-]+)\s*$", body, flags=re.M)
    for header in HEADERS:
        if header not in listed:
            failures.append(f"auth-node authResponseHeaders does not list {header}")

# --- strip-proxy-identity deletes both, on every image ---------------------
strip = [i for i, l in enumerate(lines) if re.match(r"^\s*strip-proxy-identity:\s*$", l)]
if len(strip) != 1:
    failures.append(f"expected one strip-proxy-identity middleware, found {len(strip)}")
else:
    body = block(lines, strip[0])
    for header in HEADERS:
        if not re.search(rf'^\s*{header}:\s*""\s*$', body, flags=re.M):
            failures.append(f'strip-proxy-identity does not set {header}: "" (delete)')
    # Rendered on every image: no open `{% if %}` may enclose it.
    before = template[: template.index(lines[strip[0]])]
    depth = len(re.findall(r"\{%-?\s*if\b", before)) - len(re.findall(r"\{%-?\s*endif\b", before))
    if depth != 0:
        failures.append("strip-proxy-identity sits inside a {% if %}; every image's entrypoints reference it")

# --- attached to every entrypoint ------------------------------------------
static = strip_comments(open(static_path, encoding="utf-8").read())
slines = static.splitlines()
try:
    ep_start = next(i for i, l in enumerate(slines) if re.match(r"^entryPoints:\s*$", l))
except StopIteration:
    failures.append("traefik-config.yml has no entryPoints")
    ep_start = None
if ep_start is not None:
    entrypoints = block(slines, ep_start).splitlines()
    names = [
        (i, m.group(1))
        for i, l in enumerate(entrypoints)
        if (m := re.match(r"^  ([A-Za-z0-9_-]+):\s*$", l))
    ]
    if not names:
        failures.append("traefik-config.yml declares no entrypoints")
    for i, name in names:
        body = block(entrypoints, i)
        if not re.search(r"^\s*-\s*strip-proxy-identity@file\s*$", body, flags=re.M):
            failures.append(f"entrypoint {name} does not run strip-proxy-identity@file")

# --- merod knows the key -----------------------------------------------------
def parse(version):
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-rc\.(\d+))?", version)
    if not m:
        return None
    major, minor, patch, rc = m.groups()
    return (int(major), int(minor), int(patch), int(rc) if rc is not None else float("inf"))

merod = json.load(open(versions_path, encoding="utf-8")).get("merodVersion", "")
floor = "0.11.0-rc.60"
parsed = parse(merod)
if parsed is None:
    failures.append(f"merodVersion {merod!r} is not a version this check can compare")
elif parsed < parse(floor):
    failures.append(
        f"merodVersion {merod} predates {floor}, the first merod that reads "
        "server.proxy_identity; with device-key login on, it would answer every "
        "tenant's session node-wide"
    )

if failures:
    for line in failures:
        print(f"FAIL {line}")
    sys.exit(1)

print("ok   auth-node replaces X-Auth-Account and X-Auth-Device")
print("ok   strip-proxy-identity deletes both, on every image")
print("ok   every entrypoint runs strip-proxy-identity")
print(f"ok   merod {merod} reads server.proxy_identity")
PY
