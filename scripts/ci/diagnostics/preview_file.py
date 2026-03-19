#!/usr/bin/env python3
"""Print bounded previews from text files for diagnostics."""

from __future__ import annotations

import argparse
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Preview text file content safely.")
    parser.add_argument("--file", required=True)
    parser.add_argument("--head-chars", type=int, default=0)
    parser.add_argument("--tail-lines", type=int, default=0)
    parser.add_argument("--single-line", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    path = Path(args.file)
    if not path.exists():
        print("(missing)")
        return 0
    text = path.read_text(encoding="utf-8", errors="replace")

    if args.tail_lines > 0:
        lines = text.splitlines()
        print("\n".join(lines[-args.tail_lines :]))
        return 0

    if args.head_chars > 0:
        preview = text[: args.head_chars]
        if args.single_line:
            preview = preview.replace("\n", " ")
        print(preview)
        return 0

    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
