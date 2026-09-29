#!/usr/bin/env bash
#
# The delegated routes exempt from `auth-node` match exactly their own paths,
# and nothing next to them.
#
# On a relay (`fleet_delegated_access`), three routers let a caller holding no
# node credential reach merod, because the request carries its own:
#
#   * `node-api-intents`             GET/POST/OPTIONS /admin-api/contexts/<64 hex>/intents
#   * `node-api-context-intents`     GET/POST/OPTIONS /admin-api/groups/<64 hex>/context-intents
#   * `node-api-governance-intents`  GET/POST/OPTIONS /admin-api/groups/<64 hex>/governance-intents
#
# These nodes run merod in proxy auth mode, so Traefik is the only guard on
# everything else. A pattern one character looser -- uppercase hex, any id
# length, a trailing slash, one more segment -- would hand a protected route
# (`/admin-api/groups/<id>/contexts`, a context DELETE) to a caller with no
# credential, and nothing else would notice.
#
# So this does not grep for the regex. It renders the routing template for a
# relay and for a non-relay, parses every router's rule, and ROUTES requests
# through them the way Traefik does: the highest-priority matching router wins
# (default priority is the rule's length), and path matchers see the path only,
# never the query string (Traefik 3 builds its routing path from
# `URL.EscapedPath()`; pkg/muxer/http/mux.go `withRoutingPath`). Each request
# below names the router it must land on, and whether that router runs
# `auth-node`.
#
# The pattern is Go RE2 in Traefik and Python `re` here. The two agree on
# everything these rules use (anchors, a character class, a bounded repeat,
# literals) except `$`, which Python also matches before a trailing newline;
# it is translated to `\Z` so the harness is no looser than Traefik.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMPLATE="$ROOT/mero-tee/ansible/roles/mero-traefik/templates/traefik-routing.yml.j2"

[ -f "$TEMPLATE" ] || { echo "FATAL: $TEMPLATE not found"; exit 1; }

python3 - "$TEMPLATE" <<'PY'
import re
import sys

raw = open(sys.argv[1], encoding="utf-8").read()
failures = []


def fail(msg):
    failures.append(msg)


# --- render ------------------------------------------------------------------
def render(relay):
    """The template with its one condition evaluated. Any other directive is a
    change this harness does not understand, and it says so rather than guess."""
    text = re.sub(r"\{#.*?#\}", "", raw, flags=re.S)
    out, stack = [], []
    for line in text.splitlines():
        m = re.match(r"^\s*\{%-?\s*(if|endif|else)\b(.*?)-?%\}\s*$", line)
        if m:
            kind, cond = m.group(1), m.group(2).strip()
            if kind == "if":
                if "fleet_delegated_access" not in cond:
                    print(f"FATAL: unknown template condition {cond!r}; teach this test about it")
                    sys.exit(1)
                stack.append(relay)
            elif kind == "else":
                stack[-1] = not stack[-1]
            else:
                stack.pop()
            continue
        if "{%" in line:
            print(f"FATAL: unexpected Jinja directive: {line.strip()}")
            sys.exit(1)
        if all(stack):
            out.append(line)
    return out


def routers_of(lines):
    lines = [re.sub(r"\s+#.*$", "", l) if not l.lstrip().startswith("#") else "" for l in lines]
    routers, current, in_routers, in_mw = {}, None, False, False
    for line in lines:
        if re.match(r"^  routers:\s*$", line):
            in_routers = True
            continue
        if in_routers and re.match(r"^  \S", line):
            break
        if not in_routers:
            continue
        m = re.match(r"^    ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            current = m.group(1)
            routers[current] = {"rule": None, "priority": None, "middlewares": []}
            in_mw = False
            continue
        if current is None:
            continue
        m = re.match(r'^      rule:\s*"(.*)"\s*$', line)
        if m:
            routers[current]["rule"] = m.group(1)
            continue
        m = re.match(r"^      priority:\s*(\d+)\s*$", line)
        if m:
            routers[current]["priority"] = int(m.group(1))
            continue
        if re.match(r"^      middlewares:\s*$", line):
            in_mw = True
            continue
        m = re.match(r"^        -\s*(\S+)\s*$", line)
        if m and in_mw:
            routers[current]["middlewares"].append(m.group(1))
            continue
        if re.match(r"^      \S", line):
            in_mw = False
    return routers


# --- the rule grammar these routers use ---------------------------------------
TOKEN = re.compile(r"\s*(?:(\()|(\))|(&&)|(\|\|)|(Path|PathPrefix|PathRegexp|Method)\(`([^`]*)`\))")


def compile_rule(rule):
    pos, tokens = 0, []
    while pos < len(rule):
        if rule[pos:].strip() == "":
            break
        m = TOKEN.match(rule, pos)
        if not m:
            raise ValueError(f"cannot parse rule at {rule[pos:]!r}")
        pos = m.end()
        if m.group(1):
            tokens.append(("(",))
        elif m.group(2):
            tokens.append((")",))
        elif m.group(3):
            tokens.append(("&&",))
        elif m.group(4):
            tokens.append(("||",))
        else:
            tokens.append(("m", m.group(5), m.group(6)))

    def matcher(kind, arg):
        if kind == "Path":
            return lambda p, meth: p == arg
        if kind == "PathPrefix":
            return lambda p, meth: p.startswith(arg)
        if kind == "Method":
            return lambda p, meth: meth == arg
        pattern = re.sub(r"(?<!\\)\$$", r"\\Z", arg)
        rx = re.compile(pattern)
        return lambda p, meth: rx.search(p) is not None

    i = 0

    def parse_or():
        nonlocal i
        left = parse_and()
        while i < len(tokens) and tokens[i][0] == "||":
            i += 1
            right = parse_and()
            left = (lambda a, b: lambda p, m: a(p, m) or b(p, m))(left, right)
        return left

    def parse_and():
        nonlocal i
        left = parse_atom()
        while i < len(tokens) and tokens[i][0] == "&&":
            i += 1
            right = parse_atom()
            left = (lambda a, b: lambda p, m: a(p, m) and b(p, m))(left, right)
        return left

    def parse_atom():
        nonlocal i
        tok = tokens[i]
        i += 1
        if tok[0] == "(":
            inner = parse_or()
            if tokens[i][0] != ")":
                raise ValueError("unbalanced parentheses")
            i += 1
            return inner
        if tok[0] == "m":
            return matcher(tok[1], tok[2])
        raise ValueError(f"unexpected token {tok}")

    fn = parse_or()
    if i != len(tokens):
        raise ValueError("trailing tokens")
    return fn


def route(routers, method, target):
    path = target.split("?", 1)[0]  # path matchers never see the query
    matched = [
        (r["priority"] if r["priority"] is not None else len(r["rule"]), name)
        for name, r in routers.items()
        if r["fn"](path, method)
    ]
    if not matched:
        return None
    return max(matched)[1]


# --- the requests -------------------------------------------------------------
CTX = "ab" * 32
GRP = "0123456789abcdef" * 4
AUTHOR = "cd" * 32
assert len(CTX) == len(GRP) == 64

EXEMPT = {"node-api-intents", "node-api-context-intents", "node-api-governance-intents"}
GUARDED = "node-api"

# (method, target, router on a relay)
RELAY_CASES = [
    # delegated execution
    ("GET", f"/admin-api/contexts/{CTX}/intents", "node-api-intents"),
    ("POST", f"/admin-api/contexts/{CTX}/intents", "node-api-intents"),
    ("OPTIONS", f"/admin-api/contexts/{CTX}/intents", "node-api-intents"),
    ("DELETE", f"/admin-api/contexts/{CTX}/intents", GUARDED),
    ("PUT", f"/admin-api/contexts/{CTX}/intents", GUARDED),
    ("GET", f"/admin-api/contexts/{CTX.upper()}/intents", GUARDED),
    ("GET", f"/admin-api/contexts/{CTX[:63]}/intents", GUARDED),
    ("GET", f"/admin-api/contexts/{CTX}a/intents", GUARDED),
    ("GET", f"/admin-api/contexts/{CTX}/intents/", GUARDED),
    ("GET", f"/admin-api/contexts/{CTX}/intents/x", GUARDED),
    ("DELETE", f"/admin-api/contexts/{CTX}", GUARDED),
    # delegated creation
    ("GET", f"/admin-api/groups/{GRP}/context-intents", "node-api-context-intents"),
    ("GET", f"/admin-api/groups/{GRP}/context-intents?author={AUTHOR}", "node-api-context-intents"),
    ("POST", f"/admin-api/groups/{GRP}/context-intents", "node-api-context-intents"),
    ("OPTIONS", f"/admin-api/groups/{GRP}/context-intents", "node-api-context-intents"),
    ("DELETE", f"/admin-api/groups/{GRP}/context-intents", GUARDED),
    ("PUT", f"/admin-api/groups/{GRP}/context-intents", GUARDED),
    ("GET", f"/admin-api/groups/{GRP.upper()}/context-intents", GUARDED),
    ("POST", f"/admin-api/groups/{GRP[:63]}/context-intents", GUARDED),
    ("POST", f"/admin-api/groups/{GRP}0/context-intents", GUARDED),
    ("POST", f"/admin-api/groups/{GRP}/context-intents/", GUARDED),
    ("POST", f"/admin-api/groups/{GRP}/context-intents/x", GUARDED),
    ("GET", f"/admin-api/groups/{GRP}/context-intents/x?author={AUTHOR}", GUARDED),
    ("POST", f"/admin-api/groups/{GRP}/context-intentsx", GUARDED),
    ("POST", f"/admin-api/groups/{GRP}/contexts", GUARDED),
    ("GET", f"/admin-api/groups/{GRP}/contexts", GUARDED),
    ("POST", f"/admin-api/groups/x/{GRP}/context-intents", GUARDED),
    ("POST", f"/prefix/admin-api/groups/{GRP}/context-intents", None),
    ("DELETE", f"/admin-api/groups/{GRP}", GUARDED),
    # delegated governance
    ("GET", f"/admin-api/groups/{GRP}/governance-intents", "node-api-governance-intents"),
    ("GET", f"/admin-api/groups/{GRP}/governance-intents?author={AUTHOR}", "node-api-governance-intents"),
    ("POST", f"/admin-api/groups/{GRP}/governance-intents", "node-api-governance-intents"),
    ("OPTIONS", f"/admin-api/groups/{GRP}/governance-intents", "node-api-governance-intents"),
    ("DELETE", f"/admin-api/groups/{GRP}/governance-intents", GUARDED),
    ("PUT", f"/admin-api/groups/{GRP}/governance-intents", GUARDED),
    ("GET", f"/admin-api/groups/{GRP.upper()}/governance-intents", GUARDED),
    ("POST", f"/admin-api/groups/{GRP[:63]}/governance-intents", GUARDED),
    ("POST", f"/admin-api/groups/{GRP}0/governance-intents", GUARDED),
    ("POST", f"/admin-api/groups/{GRP}/governance-intents/", GUARDED),
    ("POST", f"/admin-api/groups/{GRP}/governance-intents/x", GUARDED),
    ("GET", f"/admin-api/groups/{GRP}/governance-intents/x?author={AUTHOR}", GUARDED),
    ("POST", f"/admin-api/groups/{GRP}/governance-intentsx", GUARDED),
    ("POST", f"/admin-api/groups/{GRP}/members", GUARDED),
    ("GET", f"/admin-api/groups/{GRP}/members", GUARDED),
    ("DELETE", f"/admin-api/groups/{GRP}/members", GUARDED),
    ("POST", f"/admin-api/groups/x/{GRP}/governance-intents", GUARDED),
    ("POST", f"/prefix/admin-api/groups/{GRP}/governance-intents", None),
    # an id in the path must not swap the two shapes
    ("POST", f"/admin-api/contexts/{CTX}/context-intents", GUARDED),
    ("POST", f"/admin-api/groups/{GRP}/intents", GUARDED),
    ("POST", f"/admin-api/contexts/{CTX}/governance-intents", GUARDED),
]


def shown(target):
    """A target with each long hex id shortened to its length, which is the
    part of it a near miss varies."""
    return re.sub(r"[0-9a-fA-F]{60,}", lambda m: f"<{len(m.group(0))}{'HEX' if m.group(0).isupper() else 'hex'}>", target)


def check(label, routers, cases):
    for name, r in routers.items():
        if r["rule"] is None:
            fail(f"{label}: router {name} has no rule")
            continue
        try:
            r["fn"] = compile_rule(r["rule"])
        except (ValueError, re.error, IndexError) as exc:
            fail(f"{label}: router {name}: {exc}")
            r["fn"] = lambda p, m: False
    if GUARDED not in routers or "auth-node" not in routers[GUARDED]["middlewares"]:
        fail(f"{label}: the {GUARDED} catch-all must exist and run auth-node")
    for method, target, want in cases:
        before = len(failures)
        got = route(routers, method, target)
        if got != want:
            fail(f"{label}: {method} {target} -> {got}, expected {want}")
            continue
        guarded = got is not None and "auth-node" in routers[got]["middlewares"]
        if want in EXEMPT and guarded:
            fail(f"{label}: {want} runs auth-node, which makes it unreachable for its callers")
        if want == GUARDED and not guarded:
            fail(f"{label}: {method} {target} reached {got} without auth-node")
        if len(failures) == before:
            print(f"ok   {label}: {method:7} {shown(target)} -> {got}")


relay = routers_of(render(True))
for name in sorted(EXEMPT):
    r = relay.get(name)
    if r is None:
        fail(f"relay: no {name} router")
        continue
    if "PathPrefix" in (r["rule"] or ""):
        fail(f"relay: {name} must never use PathPrefix: {r['rule']}")
    if not r["middlewares"] or r["middlewares"][0] != "rate-limit-public":
        fail(f"relay: {name} must run rate-limit-public first, got {r['middlewares']}")
    if r["priority"] is None or r["priority"] <= (relay.get(GUARDED, {}).get("priority") or 0):
        fail(f"relay: {name} must sit above {GUARDED} by explicit priority")
check("relay", relay, RELAY_CASES)

# Not a relay: every shape exists only behind auth-node.
plain = routers_of(render(False))
for name in sorted(EXEMPT):
    if name in plain:
        fail(f"non-relay: {name} renders without fleet_delegated_access")
PLAIN_CASES = [(m, t, GUARDED) for m, t, w in RELAY_CASES if w in EXEMPT]
check("non-relay", plain, PLAIN_CASES)

if failures:
    for f in failures:
        print(f"FAIL {f}")
    sys.exit(1)
print("== the delegated routes serve exactly their own paths; every near miss lands on auth-node ==")
PY
