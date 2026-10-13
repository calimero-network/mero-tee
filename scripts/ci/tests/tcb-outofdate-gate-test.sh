#!/usr/bin/env bash
#
# Releases accept TCB status `outofdate` only because GCP's TDX hosts report it.
# The first probe host that reports `uptodate` must stop the release and name
# the change, so the allowlist is narrowed as soon as the hosts are patched,
# not whenever somebody remembers.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

python3 - "$ROOT/scripts/attestation/shared" <<'PY'
import contextlib
import io
import sys

sys.path.insert(0, sys.argv[1])
from extract_tdx_policy_candidates import (  # noqa: E402
    DEFAULT_ALLOWED_TCB_STATUSES,
    require_outofdate_review,
)

failures = []


def outcome(observed, allowed, keep):
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            require_outofdate_review(observed, allowed, keep_outofdate=keep)
        except RuntimeError as err:
            return str(err)
    return None


cases = [
    # (observed, allowed, keep_outofdate, should_fail, why)
    (["outofdate"], ["uptodate", "outofdate"], False, False, "today's fleet: outofdate observed and allowed"),
    (["uptodate"], ["uptodate", "outofdate"], False, True, "a patched probe host while outofdate is still allowed"),
    (["uptodate"], ["uptodate", "outofdate"], True, False, "--keep-outofdate lets the release through"),
    (["uptodate"], ["uptodate"], False, False, "outofdate already dropped"),
    ([], ["uptodate", "outofdate"], False, False, "no status reported (--allow-missing-tcb)"),
    (["outofdate", "uptodate"], ["uptodate", "outofdate"], False, True, "any candidate reporting uptodate"),
]
for observed, allowed, keep, should_fail, why in cases:
    err = outcome(observed, allowed, keep)
    if should_fail and err is None:
        failures.append(f"did not fail: {why}")
    elif not should_fail and err is not None:
        failures.append(f"failed: {why}: {err}")
    elif should_fail and "DEFAULT_ALLOWED_TCB_STATUSES" not in err:
        failures.append(f"failure does not name the change to make: {why}")

if "uptodate" not in DEFAULT_ALLOWED_TCB_STATUSES:
    failures.append("DEFAULT_ALLOWED_TCB_STATUSES must keep uptodate, the floor core enforces")

if failures:
    for f in failures:
        print(f"FAIL: {f}")
    sys.exit(1)
print(f"OK: a probe reporting uptodate stops a release that still accepts outofdate (default {DEFAULT_ALLOWED_TCB_STATUSES})")
PY
