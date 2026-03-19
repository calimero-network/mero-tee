#!/usr/bin/env python3
"""Poll an HTTP endpoint with transition-aware logging."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

from _util import get_nested, should_log


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Poll HTTP endpoint for readiness.")
    parser.add_argument("--url", required=True)
    parser.add_argument("--timeout-seconds", type=int, required=True)
    parser.add_argument("--interval-seconds", type=int, default=5)
    parser.add_argument("--request-timeout-seconds", type=int, default=8)
    parser.add_argument("--expected-status", type=int, default=200)
    parser.add_argument("--expect-json-key", default="")
    parser.add_argument("--expect-json-value", default="")
    parser.add_argument("--output-body", default="")
    parser.add_argument("--output-json", default="")
    parser.add_argument("--heartbeat-interval", type=int, default=10)
    parser.add_argument("--label", default="HTTP poll")
    parser.add_argument("--verbosity", default="compact", choices=["compact", "debug"])
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    deadline = time.time() + args.timeout_seconds
    attempt = 0
    last_state = ""

    if args.output_json:
        Path(args.output_json).parent.mkdir(parents=True, exist_ok=True)

    while time.time() < deadline:
        attempt += 1
        status = "error"
        body_text = ""
        detail = ""
        try:
            req = urllib.request.Request(args.url, method="GET")
            with urllib.request.urlopen(req, timeout=args.request_timeout_seconds) as resp:
                status = str(resp.getcode())
                body_text = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as err:  # status code errors still include body
            status = str(err.code)
            body_text = err.read().decode("utf-8", errors="replace")
            detail = f"http-error:{err.code}"
        except Exception as err:  # network/timeouts
            detail = f"{type(err).__name__}"

        if args.output_body:
            Path(args.output_body).write_text(body_text, encoding="utf-8")

        state = f"status={status}"
        if should_log(args.verbosity, state, last_state, attempt, args.heartbeat_interval):
            extra = f" {detail}" if detail else ""
            print(f"[INFO] {args.label}: {state} (attempt {attempt}){extra}")
        last_state = state

        status_ok = status == str(args.expected_status)
        payload_ok = True
        if status_ok and args.expect_json_key:
            try:
                parsed = json.loads(body_text or "{}")
            except json.JSONDecodeError:
                payload_ok = False
            else:
                value = get_nested(parsed, args.expect_json_key)
                payload_ok = str(value) == args.expect_json_value

        if status_ok and payload_ok:
            print(f"[OK] {args.label}: ready at attempt {attempt}")
            if args.output_json:
                Path(args.output_json).write_text(
                    json.dumps(
                        {
                            "success": True,
                            "attempts": attempt,
                            "status": status,
                            "url": args.url,
                        },
                        indent=2,
                    )
                    + "\n",
                    encoding="utf-8",
                )
            return 0

        time.sleep(max(1, args.interval_seconds))

    print(f"[FAIL] {args.label}: timeout after {attempt} attempts")
    if args.output_json:
        Path(args.output_json).write_text(
            json.dumps(
                {
                    "success": False,
                    "attempts": attempt,
                    "status": last_state.replace("status=", "") if last_state else "",
                    "url": args.url,
                    "reason": "timeout",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
