#!/usr/bin/env python3
"""Write a standardized workflow summary section to GITHUB_STEP_SUMMARY."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Write workflow summary markdown.")
    parser.add_argument("--input-json", help="Summary JSON payload path.")
    parser.add_argument("--output", required=True, help="Summary markdown output path.")
    parser.add_argument("--title", default="Workflow Summary", help="Summary title.")
    parser.add_argument("--inputs-line", action="append", default=[])
    parser.add_argument("--checks-line", action="append", default=[])
    parser.add_argument("--result-line", action="append", default=[])
    parser.add_argument("--artifacts-line", action="append", default=[])
    parser.add_argument("--next-line", action="append", default=[])
    return parser.parse_args()


def normalize_lines(raw_lines: object) -> list[str]:
    if raw_lines is None:
        return []
    if isinstance(raw_lines, list):
        return [str(item) for item in raw_lines]
    return [str(raw_lines)]


def main() -> int:
    args = parse_args()
    if args.input_json:
        payload = json.loads(Path(args.input_json).read_text(encoding="utf-8"))
        title = str(payload.get("title", args.title))
        sections = payload.get("sections", [])
    else:
        sections = [
            {"name": "Inputs / Targets", "lines": args.inputs_line},
            {"name": "Check Outcomes", "lines": args.checks_line},
            {"name": "Result", "lines": args.result_line},
            {"name": "Artifacts", "lines": args.artifacts_line},
            {"name": "Next", "lines": args.next_line},
        ]
        title = args.title

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("a", encoding="utf-8") as fh:
        fh.write(f"## {title}\n\n")
        for section in sections:
            if not isinstance(section, dict):
                continue
            name = str(section.get("name", "")).strip()
            lines = normalize_lines(section.get("lines"))
            if not lines and name:
                continue
            if name:
                fh.write(f"### {name}\n\n")
            for line in lines:
                fh.write(f"{line}\n")
            fh.write("\n")

    print(f"[INFO] wrote workflow summary to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
