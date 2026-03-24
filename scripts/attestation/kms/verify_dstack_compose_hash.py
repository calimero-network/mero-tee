#!/usr/bin/env python3
"""Verify dstack attestation path and extract compose_hash from verified event log.

Security rule: compose_hash is trustworthy only when extracted from a successfully
verified attestation path (quote_verified + event_log_verified + os_image_hash_verified).

This script:
1. Assumes quote was already verified externally (e.g. via ITA).
2. Replays RTMR3 from event_log and verifies it matches **RTMR3 parsed from the TD quote
   bytes** in ``attest-response`` (same ground truth as policy extraction). ITA JWT claims
   are not used for RTMR comparison — their layout can disagree with the quote blob.
3. Optionally replays RTMR0/1/2 and verifies they match the TD quote (``--require-os-image-hash``).
4. Extracts compose_hash and app_id from the verified event log.

Output: kms-app-identity.json with compose_hash (64-char hex), app_id (optional).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

_SHARED_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shared")
if _SHARED_DIR not in sys.path:
    sys.path.insert(0, _SHARED_DIR)
from extract_tdx_policy_candidates import measurements_from_quote

INIT_MR = "0" * 96  # 48 bytes hex = 96 chars
COMPOSE_HASH_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, payload: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")


def find_rtmr3_in_claims(claims: Any) -> Optional[str]:
    """Extract RTMR3 (96-char hex) from ITA claims: canonical keys first, else lexicographically first path."""
    if isinstance(claims, dict):
        for key in ("tdx_rtmr3", "tdx_rtmr_3", "rt_mr3", "rtmr3", "rtmr_3"):
            v = claims.get(key)
            if isinstance(v, str):
                norm = v.strip()
                if re.match(r"^[A-Fa-f0-9]{96}$", norm):
                    return norm.lower()
    paths: List[Tuple[str, str]] = []
    for path, value in _walk_json(claims):
        if not isinstance(value, str):
            continue
        norm = value.strip()
        if not re.match(r"^[A-Fa-f0-9]{96}$", norm):
            continue
        key = path.split(".")[-1].lower()
        if "rtmr3" in key or "rt_mr3" in key or "rtmr" in key or "rt_mr" in key:
            paths.append((path, norm.lower()))
    if not paths:
        return None
    return sorted(paths, key=lambda x: x[0])[0][1]


def _walk_json(value: Any, path: str = "$"):
    yield path, value
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _walk_json(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _walk_json(v, f"{path}[{i}]")


def _event_digest_input(event: Dict[str, Any]) -> bytes:
    """Build digest input per dstack: event_type:event:payload.
    Supports event_type/eventType and event_payload/eventPayload (matches attestation verifier)."""
    event_type = event.get("event_type") or event.get("eventType") or 0
    if not isinstance(event_type, int):
        event_type = int(event_type) if event_type else 0
    event_name = event.get("event", "")
    event_payload = event.get("event_payload") or event.get("eventPayload") or ""
    if isinstance(event_payload, str):
        payload_str = event_payload.strip()
        try:
            payload_bytes = bytes.fromhex(payload_str) if payload_str else b""
        except ValueError:
            payload_bytes = event_payload.encode("utf-8")
    else:
        payload_bytes = b""
    return (
        event_type.to_bytes(4, "little")
        + b":"
        + event_name.encode("utf-8")
        + b":"
        + payload_bytes
    )


def compute_event_digest(event: Dict[str, Any]) -> str:
    """Compute digest per dstack: sha384(event_type:event:payload) → 96-char hex."""
    return hashlib.sha384(_event_digest_input(event)).hexdigest()


def validate_event_digest(event: Dict[str, Any]) -> bool:
    """Validate event digest per dstack: sha384(event_type:event:payload)."""
    calculated = compute_event_digest(event)
    expected = event.get("digest", "")
    if isinstance(expected, str) and len(expected) == 96:
        return calculated == expected.lower()
    return False


def _digest_for_replay(event: Dict[str, Any]) -> str:
    """Get digest for RTMR extend: use event digest if present and valid, else compute.
    Phala imr==3 events often have empty digest; we compute from event_type:event:payload."""
    expected = event.get("digest") or ""
    if isinstance(expected, str) and len(expected) == 96:
        calculated = compute_event_digest(event)
        if calculated == expected.lower():
            return expected.lower()
        raise ValueError(f"Digest mismatch for event {event.get('event')}")
    return compute_event_digest(event)


def replay_rtmr(events: List[Dict], imr: int) -> str:
    """Replay RTMR for given IMR index. Returns 96-char hex."""
    mr = bytes.fromhex(INIT_MR)
    for event in events:
        if event.get("imr") != imr:
            continue
        digest_hex = _digest_for_replay(event)
        try:
            content_bytes = bytes.fromhex(digest_hex)
        except ValueError:
            raise ValueError(f"Invalid digest hex for event {event.get('event')}")
        if len(content_bytes) < 48:
            content_bytes = content_bytes.ljust(48, b"\0")
        mr = hashlib.sha384(mr + content_bytes).digest()
    return mr.hex()


def _rtmr_hex_from_td_quote_attest(attest: Any, imr: int) -> str:
    """96-char lowercase hex RTMR from merod/KMS attest JSON (quote body or ``quoteB64``)."""
    meas, _ = measurements_from_quote(attest)
    key = f"rtmr{imr}"
    if key not in meas:
        raise RuntimeError(f"Could not extract RTMR{imr} from TD quote (merod/KMS attest JSON)")
    return meas[key][0].lower()


def extract_compose_hash_and_app_id(events: List[Dict]) -> tuple[Optional[str], Optional[str]]:
    """Extract compose_hash and app_id from event log."""
    compose_hash = None
    app_id = None
    for event in events:
        if event.get("imr") != 3:
            continue
        name = event.get("event", "")
        payload = event.get("event_payload") or event.get("eventPayload") or ""
        if isinstance(payload, str):
            payload = payload.strip()
        if name == "compose-hash" and payload and COMPOSE_HASH_RE.match(payload):
            compose_hash = payload.lower()
        elif name == "app-id" and payload:
            app_id = payload if isinstance(payload, str) else str(payload)
    return compose_hash, app_id


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify dstack event log and extract compose_hash from verified path"
    )
    parser.add_argument(
        "--attest-response",
        required=True,
        help="Path to attest-response.json from KMS /attest",
    )
    parser.add_argument(
        "--claims",
        required=True,
        help="Path to external-attestation-token-claims.json (ITA)",
    )
    parser.add_argument(
        "--output-json",
        required=True,
        help="Output kms-app-identity.json path",
    )
    parser.add_argument(
        "--require-os-image-hash",
        action="store_true",
        default=False,
        help="Require RTMR0/1/2 replay to match quote (stricter; default: RTMR3 only)",
    )
    args = parser.parse_args()

    attest = load_json(args.attest_response)
    claims = load_json(args.claims)

    ita_rtmr3 = find_rtmr3_in_claims(claims)

    event_log = attest.get("event_log") or attest.get("eventLog")
    if event_log is None:
        raise RuntimeError("attest-response missing event_log")
    if isinstance(event_log, str):
        event_log = json.loads(event_log)
    if not isinstance(event_log, list):
        raise RuntimeError("event_log must be a JSON array")

    quote_rtmr3 = _rtmr_hex_from_td_quote_attest(attest, 3)
    if ita_rtmr3 and ita_rtmr3 != quote_rtmr3:
        print(
            "WARNING: ITA JWT RTMR3 differs from TD-quote RTMR3; using TD quote for replay check",
            file=sys.stderr,
        )

    replayed_rtmr3 = replay_rtmr(event_log, 3)
    if replayed_rtmr3 != quote_rtmr3:
        raise RuntimeError(
            f"Event log RTMR3 replay mismatch: replayed={replayed_rtmr3[:32]}... "
            f"quote_td={quote_rtmr3[:32]}..."
        )

    if args.require_os_image_hash:
        for imr in (0, 1, 2):
            quote_val = _rtmr_hex_from_td_quote_attest(attest, imr)
            replayed = replay_rtmr(event_log, imr)
            if replayed != quote_val:
                raise RuntimeError(
                    f"Event log RTMR{imr} replay mismatch for imr={imr}"
                )

    compose_hash, app_id = extract_compose_hash_and_app_id(event_log)
    if not compose_hash:
        raise RuntimeError("Could not extract compose_hash from verified event log")

    output = {
        "schema_version": 1,
        "compose_hash": compose_hash,
        "app_id": app_id,
        "quote_verified": True,
        "event_log_verified": True,
        "os_image_hash_verified": args.require_os_image_hash,
    }
    save_json(args.output_json, output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
