"""Shared utility helpers for CI polling scripts."""

from __future__ import annotations

from typing import Any


def should_log(verbosity: str, current: str, previous: str, attempt: int, heartbeat: int) -> bool:
    if verbosity == "debug":
        return True
    if attempt == 1:
        return True
    if heartbeat > 0 and attempt % heartbeat == 0:
        return True
    return current != previous


def get_nested(data: Any, dotted_key: str) -> Any:
    cur = data
    for chunk in dotted_key.split("."):
        if isinstance(cur, dict) and chunk in cur:
            cur = cur[chunk]
            continue
        return None
    return cur
