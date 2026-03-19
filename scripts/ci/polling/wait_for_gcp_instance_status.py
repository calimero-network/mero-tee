#!/usr/bin/env python3
"""Wait for a GCP instance to reach a target status with transition logs."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Wait for GCP instance status.")
    parser.add_argument("--instance", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--zone", required=True)
    parser.add_argument("--target-status", default="RUNNING")
    parser.add_argument("--attempts", type=int, default=30)
    parser.add_argument("--sleep-seconds", type=int, default=10)
    parser.add_argument("--heartbeat-interval", type=int, default=5)
    parser.add_argument("--verbosity", default="compact", choices=["compact", "debug"])
    parser.add_argument("--output-json", default="")
    return parser.parse_args()


def should_log(verbosity: str, current: str, previous: str, attempt: int, heartbeat: int) -> bool:
    if verbosity == "debug":
        return True
    if attempt == 1:
        return True
    if heartbeat > 0 and attempt % heartbeat == 0:
        return True
    return current != previous


def query_status(instance: str, project: str, zone: str) -> str:
    cmd = [
        "gcloud",
        "compute",
        "instances",
        "describe",
        instance,
        "--project",
        project,
        "--zone",
        zone,
        "--format=value(status)",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return "UNKNOWN"
    return proc.stdout.strip() or "UNKNOWN"


def main() -> int:
    args = parse_args()
    last_status = ""
    final_status = "UNKNOWN"
    reached_at = 0

    for attempt in range(1, args.attempts + 1):
        status = query_status(args.instance, args.project, args.zone)
        final_status = status
        if should_log(args.verbosity, status, last_status, attempt, args.heartbeat_interval):
            print(f"[INFO] VM status: {status} (attempt {attempt}/{args.attempts})")
        last_status = status
        if status == args.target_status:
            reached_at = attempt
            print(f"[OK] VM reached {args.target_status} at attempt {attempt}/{args.attempts}")
            break
        if attempt < args.attempts:
            time.sleep(max(1, args.sleep_seconds))

    success = reached_at > 0
    if args.output_json:
        Path(args.output_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output_json).write_text(
            json.dumps(
                {
                    "success": success,
                    "status": final_status,
                    "attempts": reached_at if success else args.attempts,
                    "target_status": args.target_status,
                    "instance": args.instance,
                    "project": args.project,
                    "zone": args.zone,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    if success:
        return 0
    print(f"[FAIL] VM did not reach {args.target_status} in {args.attempts} attempts")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
