#!/usr/bin/env python3
"""Build a compact artifacts index for workflow diagnostics."""

from __future__ import annotations

import argparse
import datetime as dt
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build artifact index file.")
    parser.add_argument("--output", required=True, help="Output index path.")
    parser.add_argument(
        "--entry",
        action="append",
        default=[],
        help="Artifact entry in 'relative/path|description' form. Repeatable.",
    )
    parser.add_argument(
        "--base-dir",
        default=".",
        help="Base directory used to check artifact file presence.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    output_path = Path(args.output)
    base_dir = Path(args.base_dir)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []
    lines.append(f"# artifacts index generated at {dt.datetime.now(dt.timezone.utc).isoformat()}")
    lines.append("# format: path|present|description")

    for raw_entry in args.entry:
        if "|" in raw_entry:
            rel_path, description = raw_entry.split("|", 1)
        else:
            rel_path, description = raw_entry, ""
        rel_path = rel_path.strip()
        description = description.strip()
        if not rel_path:
            continue
        present = "yes" if (base_dir / rel_path).exists() else "no"
        lines.append(f"{rel_path}|{present}|{description}")

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[ARTIFACT] wrote artifact index to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
