#!/usr/bin/env python3
"""Poll candidate base URLs until a health endpoint satisfies readiness checks."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Poll candidate URLs for health readiness.")
    parser.add_argument("--candidates-json", required=True, help="JSON file with {urls:[...]} payload.")
    parser.add_argument("--path", default="/health", help="Path appended to each candidate.")
    parser.add_argument("--timeout-seconds", type=int, required=True)
    parser.add_argument("--interval-seconds", type=int, default=5)
    parser.add_argument("--max-time-per-request", type=int, default=8)
    parser.add_argument("--expected-status", type=int, default=200)
    parser.add_argument("--expect-json-key", default="")
    parser.add_argument("--expect-json-value", default="")
    parser.add_argument("--output-body", default="")
    parser.add_argument("--output-json", default="")
    parser.add_argument("--heartbeat-interval", type=int, default=10)
    parser.add_argument("--verbosity", default="compact", choices=["compact", "debug"])
    return parser.parse_args()


def get_nested(data: Any, dotted_key: str) -> Any:
    cur = data
    for chunk in dotted_key.split("."):
        if isinstance(cur, dict) and chunk in cur:
            cur = cur[chunk]
            continue
        return None
    return cur


def should_log(verbosity: str, current: str, previous: str, attempt: int, heartbeat: int) -> bool:
    if verbosity == "debug":
        return True
    if attempt == 1:
        return True
    if heartbeat > 0 and attempt % heartbeat == 0:
        return True
    return current != previous


def main() -> int:
    args = parse_args()
    payload = json.loads(Path(args.candidates_json).read_text(encoding="utf-8"))
    candidates = payload.get("urls", [])
    if not isinstance(candidates, list):
        candidates = []
    candidates = [str(item).rstrip("/") for item in candidates if str(item).strip()]
    if not candidates:
        print("[FAIL] candidate-health: no candidate URLs provided")
        return 1

    deadline = time.time() + args.timeout_seconds
    attempt = 0
    last_state = ""
    selected_url = ""
    last_status = ""

    while time.time() < deadline:
        for candidate in candidates:
            attempt += 1
            target_url = f"{candidate}{args.path}"
            status = "error"
            body_text = ""
            detail = ""
            try:
                req = urllib.request.Request(target_url, method="GET")
                with urllib.request.urlopen(req, timeout=args.max_time_per_request) as resp:
                    status = str(resp.getcode())
                    body_text = resp.read().decode("utf-8", errors="replace")
            except urllib.error.HTTPError as err:
                status = str(err.code)
                body_text = err.read().decode("utf-8", errors="replace")
                detail = f"http-error:{err.code}"
            except Exception as err:
                detail = type(err).__name__

            if args.output_body:
                Path(args.output_body).write_text(body_text, encoding="utf-8")

            state = f"url={candidate} status={status}"
            if should_log(args.verbosity, state, last_state, attempt, args.heartbeat_interval):
                extra = f" {detail}" if detail else ""
                print(f"[INFO] candidate-health: {state} (attempt {attempt}){extra}")
            last_state = state
            last_status = status

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
                selected_url = candidate
                break

        if selected_url:
            break
        time.sleep(max(1, args.interval_seconds))

    result = {
        "success": bool(selected_url),
        "attempts": attempt,
        "selected_url": selected_url,
        "last_status": last_status,
        "reason": "ready" if selected_url else "timeout",
    }
    if args.output_json:
        Path(args.output_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output_json).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    if selected_url:
        print(f"[OK] candidate-health: selected {selected_url} at attempt {attempt}")
        print(selected_url)
        return 0

    print(f"[FAIL] candidate-health: timeout after {attempt} attempts")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
