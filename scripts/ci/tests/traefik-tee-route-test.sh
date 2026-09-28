#!/usr/bin/env bash
#
# The public TEE router serves exactly `GET /admin-api/tee/info` and
# `POST /admin-api/tee/attest`, and nothing else under `/admin-api/tee/`.
#
# These nodes run merod in proxy auth mode, so traefik is the only guard on
# core's protected router. Everything else under `/admin-api/tee/` lives there
# (`fleet-join`, `registration-attest`) and must fall through to `node-api`,
# which sits behind `auth-node`. A prefix here, or one more exact path, would
# serve a protected route without a credential.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="$ROOT/mero-tee/ansible/roles/mero-traefik/templates/traefik-routing.yml.j2"

[ -f "$TEMPLATE" ] || { echo "FATAL: $TEMPLATE not found"; exit 1; }

python3 - "$TEMPLATE" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
# Comments explain routers and must not count as them.
text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
lines = [re.sub(r"\s+#.*$", "", l) if not l.lstrip().startswith("#") else "" for l in text.splitlines()]


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


rules = {}
current = None
for line in lines:
    m = re.match(r"^    ([A-Za-z0-9_-]+):\s*$", line)
    if m:
        current = m.group(1)
        continue
    m = re.match(r'^      rule:\s*"(.*)"\s*$', line)
    if m and current:
        rules[current] = m.group(1)

tee_rule = rules.get("node-api-tee")
if tee_rule is None:
    fail("no node-api-tee router; this test pins what it serves")
if "PathPrefix" in tee_rule or "PathRegexp" in tee_rule:
    fail(f"node-api-tee must match exact paths only: {tee_rule}")
paths = set(re.findall(r"Path\(`([^`]*)`\)", tee_rule))
if paths != {"/admin-api/tee/info", "/admin-api/tee/attest"}:
    fail(f"node-api-tee must serve exactly /admin-api/tee/info and /admin-api/tee/attest, got {sorted(paths)}")

# No other router may reach a protected TEE route without auth either.
for name, rule in rules.items():
    if name == "node-api-tee":
        continue
    for path in ("/admin-api/tee/registration-attest", "/admin-api/tee/fleet-join"):
        if f"Path(`{path}`)" in rule:
            fail(f"router {name} matches {path} exactly")
    if re.search(r"PathPrefix\(`/admin-api/tee", rule):
        fail(f"router {name} matches a /admin-api/tee prefix: {rule}")

print("PASS: the public TEE router serves only info and attest")
PY
