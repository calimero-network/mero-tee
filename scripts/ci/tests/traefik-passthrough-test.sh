#!/usr/bin/env bash
#
# Traefik passes every request to merod untouched.
#
# On a merod 1.0 node every request but `/health` and `/attestation` is a sealed
# envelope only the attested node can open, and merod authenticates its callers
# itself. Traefik is a TLS front and nothing else, so the routing file must be:
#
#   * one router, `PathPrefix(`/`)`, on both entrypoints, to one service;
#   * no middleware anywhere: no forwardAuth (there is no mero-auth), no rate
#     limit (peers share the public URL), no CORS (merod's `--origins` decides),
#     no header rewriting -- on the routers, in the routing file, or on the
#     static config's entrypoints;
#   * the Host header passed on (`--apps-domain` routes on it);
#   * pointed at merod on loopback.
#
# The template is rendered with Jinja and parsed as YAML, so what is checked is
# the file the image ships.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
ROLE="$ROOT/mero-tee/ansible/roles/mero-traefik"
INIT="$ROOT/mero-tee/ansible/roles/merotee/templates/calimero-init.sh.j2"

python3 - "$ROLE/templates/traefik-routing.yml.j2" "$ROLE/files/traefik-config.yml" "$INIT" <<'PY'
import re
import sys

import jinja2
import yaml

routing_path, static_path, init_path = sys.argv[1:4]
failures = []

rendered = jinja2.Environment(undefined=jinja2.StrictUndefined).from_string(
    open(routing_path, encoding="utf-8").read()
).render()
routing = yaml.safe_load(rendered)
static = yaml.safe_load(open(static_path, encoding="utf-8"))

http = routing.get("http", {})
routers = http.get("routers", {})
services = http.get("services", {})

if list(routers) != ["merod"]:
    failures.append(f"expected exactly one router `merod`, got {sorted(routers)}")
router = routers.get("merod", {})
if router.get("rule") != "PathPrefix(`/`)":
    failures.append(f"the router must match every path, got rule {router.get('rule')!r}")
if sorted(router.get("entryPoints", [])) != ["web", "websecure"]:
    failures.append(f"the router must serve both entrypoints, got {router.get('entryPoints')}")
if router.get("middlewares"):
    failures.append(f"the router carries middleware {router['middlewares']}")
if "middlewares" in http:
    failures.append(f"the routing file defines middleware {sorted(http['middlewares'])}")
for name, ep in (static.get("entryPoints") or {}).items():
    if (ep.get("http") or {}).get("middlewares"):
        failures.append(f"entrypoint {name} attaches middleware {ep['http']['middlewares']}")
if re.search(r"forwardAuth|rateLimit|accessControl|customRequestHeaders", rendered + open(static_path).read()):
    failures.append("forwardAuth, rateLimit, CORS or header rewriting appears in the traefik config")

if list(services) != [router.get("service")]:
    failures.append(f"the router's service {router.get('service')!r} is not the one service defined: {sorted(services)}")
lb = (services.get(router.get("service"), {}) or {}).get("loadBalancer", {})
if lb.get("passHostHeader") is False:
    failures.append("passHostHeader is off; --apps-domain frontends are routed by Host")
urls = [s.get("url") for s in lb.get("servers", [])]
if len(urls) != 1:
    failures.append(f"expected one upstream, got {urls}")
upstream = urls[0] if urls else ""
m = re.fullmatch(r"http://(127\.0\.0\.1:\d+)", upstream or "")
if not m:
    failures.append(f"the upstream must be merod on loopback over http, got {upstream!r}")

if failures:
    print("FAIL: traefik is not a plain pass-through to merod:")
    for f in failures:
        print(f"  - {f}")
    sys.exit(1)
print(f"PASS: traefik passes every request to merod at {upstream}, with no middleware")
PY
