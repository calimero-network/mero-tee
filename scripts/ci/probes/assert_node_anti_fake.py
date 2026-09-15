#!/usr/bin/env python3
"""Assert that a node's client-side anti-fake verification passed.

Consumes the JSON written by `node_anti_fake_http.py`, which is the only
producer of that file. The two post-release consumers -- the node e2e script
and the KMS-node compatibility workflow -- both call this rather than carrying
their own copy of the assertions, because carrying their own copy is what broke
them: #255 moved the anti-fake check from SSH to HTTP and renamed every field,
and both copies went on asserting the old SSH-era shape:

    checks.positive.passed                          (no producer; split into
                                                     nonce_binding + genuine_hardware)
    checks.wrong_nonce.rejected                     (producer emits .passed)
    checks.tampered_quote.rejected                  (producer emits .passed)
    checks.wrong_expected_application_hash.rejected (no producer at all)

Every one of those reads a key that does not exist, so `.get()` returned None
and the scripts could never pass -- while reporting "expected true, got None",
which names the assertion rather than the drift that caused it.

So this checks the producer's *shape* before its verdicts, and says which
checks were actually emitted when they disagree. A future rename fails with
"missing ... produced ..." naming both sides, instead of a None that reads like
a failed security property.

`wrong_expected_application_hash` is deliberately NOT asserted: the HTTP probe
has no equivalent, so there is nothing to read. It is dropped rather than left
as an assertion that can only ever be None. If that property still needs
covering it belongs in `node_anti_fake_http.py` as a real check, which is its
own change -- not a silent pass here.
"""

import argparse
import json
import pathlib
import sys

# The checks `node_anti_fake_http.py` emits, each as {"passed": bool, ...}.
# Keep in sync with that file; a mismatch is reported rather than ignored.
EXPECTED_CHECKS = (
    "nonce_binding",  # report_data carries the nonce CI chose (not a replay)
    "wrong_nonce",  # report_data does NOT match a different nonce
    "genuine_hardware",  # Intel Trust Authority validates the quote
    "tampered_quote",  # ITA REJECTS the same quote with a flipped byte
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, help="image profile under test")
    parser.add_argument("--input", required=True, help="node client verification JSON")
    parser.add_argument(
        "--log-prefix",
        default="post-release-e2e",
        help="tag for log lines, so each caller keeps its own",
    )
    args = parser.parse_args()

    tag = f"[{args.log_prefix}]"
    path = pathlib.Path(args.input)

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"{tag} ERROR: could not read anti-fake result {path}: {exc}", file=sys.stderr)
        return 1

    checks = payload.get("checks")
    if not isinstance(checks, dict):
        print(f"{tag} ERROR: {path} has no `checks` object", file=sys.stderr)
        return 1

    # Shape first. A renamed or dropped check must not read as a failed
    # security property, and must name both sides so the drift is obvious.
    missing = [name for name in EXPECTED_CHECKS if name not in checks]
    if missing:
        print(
            f"{tag} ERROR: anti-fake result for profile={args.profile} is missing "
            f"{', '.join(missing)}. Produced: {', '.join(sorted(checks)) or '(none)'}. "
            f"The producer (node_anti_fake_http.py) and EXPECTED_CHECKS in "
            f"{pathlib.Path(__file__).name} have drifted.",
            file=sys.stderr,
        )
        return 1

    # Then the verdicts. Only an explicit True passes: the producer uses None /
    # "inconclusive" where it could not establish a property, and failing to
    # establish it is not evidence for it.
    failed = []
    for name in EXPECTED_CHECKS:
        check = checks[name]
        if not isinstance(check, dict) or check.get("passed") is not True:
            detail = ""
            if isinstance(check, dict):
                verdict = check.get("ita_verdict")
                why = check.get("detail")
                detail = f" (ita_verdict={verdict!r}, detail={why!r})" if verdict or why else ""
            failed.append(f"{name}{detail}")
    if failed:
        print(
            f"{tag} ERROR: node client verification failed for profile={args.profile}: "
            + "; ".join(failed),
            file=sys.stderr,
        )
        return 1

    # Cross-check the producer's own summary. If it disagrees with the per-check
    # booleans, one of the two is wrong and neither should be trusted silently.
    outcome = payload.get("outcome")
    producer_failed = payload.get("failed_checks") or []
    if outcome != "success" or producer_failed:
        print(
            f"{tag} ERROR: every check passed but the producer reported "
            f"outcome={outcome!r} failed_checks={producer_failed!r} for "
            f"profile={args.profile}; refusing to call this a pass",
            file=sys.stderr,
        )
        return 1

    print(
        f"{tag} OK: node client-side anti-fake verification checks passed "
        f"for profile={args.profile} ({', '.join(EXPECTED_CHECKS)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
