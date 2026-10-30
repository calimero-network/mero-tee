#!/usr/bin/env python3
"""Where an mkosi build's time went, from its timestamped log.

build-image.sh prefixes every line of the build with the UTC time it was
printed ("HH:MM:SS "). This prints, at the end of the step's log:
  - each mkosi phase (its "‣ ..." headings) and how long it ran until the next;
  - the longest silences (nothing printed), with the line before and after.

A slow release then says which stretch was slow (the package download, the
tools tree, the erofs root, the UKI) in the last lines of the step, which are
also the ones the GitHub API's log tail returns.

Usage: build_timing.py LOG [--top N]
"""

from __future__ import annotations

import argparse
import re
import sys

STAMP = re.compile(r"^(\d\d):(\d\d):(\d\d) (.*)$")
# mkosi's headings: "‣ Building default image", "‣  Installing Ubuntu", ...
PHASE = re.compile(r"^\s*‣\s*(.+)$")


def parse(lines):
    """[(seconds since the first line, text)], across midnight."""
    out = []
    first = last = None
    day = 0
    for line in lines:
        m = STAMP.match(line.rstrip("\n"))
        if not m:
            continue
        t = int(m[1]) * 3600 + int(m[2]) * 60 + int(m[3]) + day
        if last is not None and t < last:
            day += 86400
            t += 86400
        if first is None:
            first = t
        last = t
        out.append((t - first, m[4]))
    return out


def phases(entries):
    """[(seconds, heading)] for each mkosi heading, until the next or the end."""
    marks = [(t, PHASE.match(text)[1].strip()) for t, text in entries if PHASE.match(text)]
    end = entries[-1][0] if entries else 0
    return [(nxt - t, name) for (t, name), nxt in zip(marks, [t for t, _ in marks[1:]] + [end])]


def silences(entries):
    """[(seconds, line before, line after)] between consecutive lines."""
    return [(b[0] - a[0], a[1], b[1]) for a, b in zip(entries, entries[1:])]


def fmt(seconds):
    return f"{seconds // 60:3d}m{seconds % 60:02d}s"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("log")
    ap.add_argument("--top", type=int, default=8)
    args = ap.parse_args(argv)
    with open(args.log, encoding="utf-8", errors="replace") as f:
        entries = parse(f)
    if not entries:
        print("build timing: no timestamped lines")
        return 0
    total = entries[-1][0]
    print(f"build timing: {fmt(total)} over {len(entries)} lines")
    ph = phases(entries)
    if ph:
        print("  mkosi phases, longest first:")
        for secs, name in sorted(ph, key=lambda p: -p[0])[: args.top]:
            print(f"    {fmt(secs)}  {name[:120]}")
    quiet = [s for s in sorted(silences(entries), key=lambda s: -s[0]) if s[0] >= 10][: args.top]
    if quiet:
        print("  longest silences (line before -> line after):")
        for secs, before, after in quiet:
            print(f"    {fmt(secs)}  {before[:110]}")
            print(f"              -> {after[:110]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
