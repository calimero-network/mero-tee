#!/usr/bin/env python3
"""Every fleet call the sidecar makes must carry `X-Fleet-Token`.

The token is the only thing authenticating a node to `/api/fleet/*`. It is
optional in the sidecar by construction -- `[[ -n "${FLEET_TOKEN:-}" ]]` gates
each header, because an image built without one has to keep working against a
manager that requires none. That makes a MISSING header invisible: the call
still succeeds today, and only starts failing once the manager has a token
configured, on a fleet of TEE VMs, long after the change that dropped it.

So the invariant is checked statically instead: a function that calls
`${MDMA_URL}/api/fleet/...` must also build the header. One function may make
several calls off one `headers` array -- `register_node` does, for the challenge
and the register POST -- so this counts functions, not call sites.

This does not verify the token is correct, only that it is offered. What it
catches is a new fleet endpoint wired up by copying a curl line instead of a
whole function.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = REPO_ROOT / "mero-tee/ansible/roles/merotee/templates/fleet-sidecar.sh.j2"

FUNC = re.compile(r"^(?:function\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{")
FLEET_CALL = re.compile(r"\$\{MDMA_URL\}/api/fleet/")
HEADER = re.compile(r"X-Fleet-Token")


def main() -> int:
    if not TEMPLATE.exists():
        print(f"[FAIL] {TEMPLATE} not found")
        return 2

    # Attribute each line to the function it sits in. Top-level lines land under
    # a synthetic name so a fleet call made outside any function is still
    # reported rather than silently skipped.
    # A function ends at a `}` in column 0. Counting brace depth instead would
    # be wrong in a shell script: `${MDMA_URL}`, `${#arr[@]}` and `${FOO:-}` all
    # carry braces that close nothing, and an early miscount silently attributes
    # the rest of the file to one function -- which is exactly what the first
    # version of this checker did, reporting every call as belonging to `log`.
    bodies: dict[str, list[str]] = {}
    current = "<top level>"
    for line in TEMPLATE.read_text().splitlines():
        match = FUNC.match(line)
        if match:
            current = match.group(1)
            continue
        if line.rstrip() == "}" and current != "<top level>":
            current = "<top level>"
            continue
        bodies.setdefault(current, []).append(line)

    callers = {name: body for name, body in bodies.items() if any(FLEET_CALL.search(l) for l in body)}
    if not callers:
        print("[FAIL] no fleet calls found at all — has the template moved?")
        return 1

    missing = [name for name, body in callers.items() if not any(HEADER.search(l) for l in body)]
    for name in sorted(callers):
        mark = "FAIL" if name in missing else " OK "
        calls = sum(1 for l in callers[name] if FLEET_CALL.search(l))
        print(f"[{mark}] {name}  ({calls} fleet call(s))")

    if missing:
        print()
        for name in sorted(missing):
            print(f"[FAIL] {name} calls /api/fleet/* without offering X-Fleet-Token.")
        print("Add: local headers=(); [[ -n \"${FLEET_TOKEN:-}\" ]] && headers+=(-H \"X-Fleet-Token: ${FLEET_TOKEN}\")")
        return 1

    print(f"\nAll {len(callers)} fleet-calling function(s) offer the token.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
