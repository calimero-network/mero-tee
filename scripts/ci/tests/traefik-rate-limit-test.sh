#!/usr/bin/env bash
#
# Every router on the node ingress must carry a request-rate limit, and carry it
# FIRST.
#
# Two of these routes verify signatures for callers holding no credential, by
# design. That makes an unlimited ingress a way to spend a node's CPU from
# anywhere, and the routing template's own comments called it a surface "worth
# watching" while nothing watched it.
#
# The ordering half is the part that drifts silently. Traefik runs a middleware
# chain in order, so a limit placed after `auth-node` pays for a forwardAuth
# subrequest on every flooded request — a flood of the node becomes a flood of
# its auth service too, and the limit that was supposed to prevent that is what
# schedules it.
#
# The router count is pinned deliberately. A new router is the way this
# invariant gets lost, and a failure here naming the count is a cheaper place to
# learn it than a node under load.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="$ROOT/mero-tee/ansible/roles/mero-traefik/templates/traefik-routing.yml.j2"

[ -f "$TEMPLATE" ] || { echo "FATAL: $TEMPLATE not found"; exit 1; }

python3 - "$TEMPLATE" <<'PY'
import re
import sys

EXPECTED_ROUTERS = 9

# The tight tier, for routes reachable with no credential at all. Both verify
# signatures before refusing, so these are the two an anonymous caller can make
# do real work.
TIGHT = {"node-api-intents", "node-api-admit"}

text = open(sys.argv[1], encoding="utf-8").read()
# Jinja controls which routers render; the invariant applies to every branch, so
# the directives are stripped rather than evaluated.
text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
text = re.sub(r"\{%.*?%\}", "", text, flags=re.S)

body = text.split("routers:", 1)[1].split("  services:", 1)[0]

# Routers are the 4-space keys; everything below them is deeper.
blocks = re.split(r"\n    (?=[a-z0-9-]+:\s*\n)", body)
routers = {}
for block in blocks:
    name = re.match(r"\s*([a-z0-9-]+):", block)
    if not name:
        continue
    mw = re.search(r"\n      middlewares:\n((?:\s*#.*\n|\s+- \S+\n)+)", block)
    entries = re.findall(r"- (\S+)", mw.group(1)) if mw else []
    routers[name.group(1)] = entries

failures = []

if len(routers) != EXPECTED_ROUTERS:
    failures.append(
        f"expected {EXPECTED_ROUTERS} routers, found {len(routers)}: "
        f"{sorted(routers)}. A router was added or removed — give it a rate "
        f"limit and update EXPECTED_ROUTERS in this test."
    )

for name, entries in sorted(routers.items()):
    if not entries:
        failures.append(f"{name}: no middlewares at all, so no rate limit")
        continue
    first = entries[0]
    if not first.startswith("rate-limit"):
        failures.append(
            f"{name}: first middleware is {first!r}, not a rate limit. "
            f"Chain order decides what a flood costs before it is refused."
        )
        continue
    want = "rate-limit-public" if name in TIGHT else "rate-limit"
    if first != want:
        failures.append(f"{name}: expected {want!r} tier, found {first!r}")

for name in sorted(TIGHT):
    if name not in routers:
        failures.append(
            f"{name}: expected an unauthenticated route by this name. If it was "
            f"renamed, update TIGHT — a credential-free route that drops off "
            f"this list silently loses its tighter limit."
        )

if failures:
    for line in failures:
        print(f"FAIL {line}")
    sys.exit(1)

for name, entries in sorted(routers.items()):
    print(f"ok   {name}: {entries[0]} first")
print(f"== {len(routers)} routers, every one rate limited ==")
PY
