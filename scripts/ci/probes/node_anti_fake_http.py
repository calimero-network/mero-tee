#!/usr/bin/env python3
"""Anti-fake checks against a node's TDX attestation, over HTTP only.

Replaces the SSH + ``merod tee probe`` approach (#251). Two reasons:

1. It could never cover ``locked-read-only``. That profile's whole point is that
   ``merod-lockdown`` removes openssh (hardening rule R1) and
   ``merotee-conformance`` asserts it is gone, so an SSH-based check cannot run
   on the one profile whose assurance matters most.
2. It asked the node to grade itself. ``merod tee probe`` runs the verification
   *on the node* and reports the verdict; a node that lies about its own quote
   would also lie about the self-check. Here CI does the verifying, and the only
   thing the node supplies is the quote.

Checks, in the order they are reported:

``nonce_binding``   the quote's report_data must carry the nonce CI just chose,
                    so the quote is fresh rather than replayed.
``wrong_nonce``     report_data must NOT match a different nonce -- the explicit
                    negative for the check above.
``genuine_hardware``Intel Trust Authority must validate the quote. This is what
                    rules out a mock or fabricated quote, and it is stronger
                    than the old ``is_mock`` field because it does not take the
                    node's word for anything.
``tampered_quote``  ITA must REJECT a quote with a flipped byte, proving the
                    signature actually gates the result rather than the endpoint
                    returning success regardless.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from typing import Any, Dict, Optional, Tuple

sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "attestation", "shared"),
)

from verify_tdx_quote_ita import (  # noqa: E402
    decode_base64_flexible,
    find_token,
    post_json,
)

NONCE_BYTES = 32


def fail(code: str, message: str) -> None:
    print(f"::error::[{code}] {message}")
    print(f"[FAIL] code={code} {message}")


def attest(base_url: str, nonce_hex: str, timeout: int) -> Tuple[int, str]:
    status, _headers, body = post_json(
        url=f"{base_url.rstrip('/')}/admin-api/tee/attest",
        api_key="",
        payload={"nonce": nonce_hex},
        timeout=timeout,
    )
    return status, body


def ita_verdict(
    ita_url: str, ita_api_key: str, quote_b64: str, timeout: int
) -> Tuple[str, Optional[int], str]:
    """Return (verdict, http_status, detail).

    verdict is "accepted" when ITA issued a token, "rejected" when ITA answered
    but declined, and "inconclusive" when we could not get an answer at all.
    An inconclusive result must never be read as either -- a flaky network is
    not evidence that a tampered quote was caught.
    """
    status, _headers, body = post_json(
        url=ita_url, api_key=ita_api_key, payload={"quote": quote_b64}, timeout=timeout
    )
    if status == 0:
        return "inconclusive", None, body
    if status >= 500:
        return "inconclusive", status, body[:400]
    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        payload = body
    if 200 <= status < 300 and isinstance(payload, (dict, list)) and find_token(payload):
        return "accepted", status, ""
    return "rejected", status, (body[:400] if isinstance(body, str) else "")


def flip_a_byte(quote_b64: str) -> Optional[str]:
    import base64

    raw = decode_base64_flexible(quote_b64)
    if not raw or len(raw) < 600:
        return None
    mutated = bytearray(raw)
    # Inside the report body rather than the header, so the payload stays
    # structurally parseable and ITA has to reject it on the signature rather
    # than bouncing it as malformed -- which would prove nothing.
    mutated[500] ^= 0xFF
    return base64.b64encode(bytes(mutated)).decode("ascii")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--ita-url", required=True)
    ap.add_argument("--ita-api-key", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--timeout", type=int, default=60)
    args = ap.parse_args()

    checks: Dict[str, Any] = {}
    nonce_hex = secrets.token_bytes(NONCE_BYTES).hex()

    status, body = attest(args.base_url, nonce_hex, args.timeout)
    if status < 200 or status >= 300:
        fail("ANTI_FAKE_ATTEST_HTTP", f"/admin-api/tee/attest returned HTTP {status}: {body[:300]}")
        return 1
    try:
        resp = json.loads(body)
    except json.JSONDecodeError:
        fail("ANTI_FAKE_ATTEST_PARSE", "attest response was not JSON")
        return 1

    data = resp.get("data") if isinstance(resp, dict) else None
    if not isinstance(data, dict):
        fail("ANTI_FAKE_ATTEST_PARSE", "attest response has no `data` object")
        return 1
    quote_b64 = data.get("quoteB64") or data.get("quote_b64") or ""
    report_data = ((data.get("quote") or {}).get("body") or {}).get("reportdata") or ""
    if not quote_b64 or not report_data:
        fail("ANTI_FAKE_ATTEST_PARSE", "attest response is missing quoteB64 or quote.body.reportdata")
        return 1

    bound = report_data.strip().lower().removeprefix("0x")[: NONCE_BYTES * 2]
    checks["nonce_binding"] = {"passed": bound == nonce_hex, "expected": nonce_hex, "observed": bound}

    flipped = bytearray(bytes.fromhex(nonce_hex))
    flipped[0] ^= 0xFF
    checks["wrong_nonce"] = {"passed": bound != flipped.hex(), "rejected_nonce": flipped.hex()}

    verdict, http_status, detail = ita_verdict(args.ita_url, args.ita_api_key, quote_b64, args.timeout)
    checks["genuine_hardware"] = {
        "passed": verdict == "accepted",
        "ita_verdict": verdict,
        "http_status": http_status,
        "detail": detail,
    }

    mutated = flip_a_byte(quote_b64)
    if mutated is None:
        checks["tampered_quote"] = {"passed": False, "ita_verdict": "not_attempted", "detail": "quote too short to mutate"}
    else:
        t_verdict, t_status, t_detail = ita_verdict(args.ita_url, args.ita_api_key, mutated, args.timeout)
        checks["tampered_quote"] = {
            # Only an explicit rejection passes. "inconclusive" is a failure to
            # establish the property, not evidence for it.
            "passed": t_verdict == "rejected",
            "ita_verdict": t_verdict,
            "http_status": t_status,
            "detail": t_detail,
        }

    failed = [name for name, c in checks.items() if not c["passed"]]
    result = {
        "outcome": "success" if not failed else "failure",
        "failed_checks": failed,
        "nonce": nonce_hex,
        "base_url": args.base_url,
        "checks": checks,
    }
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    print("=== node anti-fake checks (client-side, over HTTP) ===")
    for name, c in checks.items():
        print(f"  {'PASS' if c['passed'] else 'FAIL'}  {name}" + (f"  ({c.get('ita_verdict')})" if c.get("ita_verdict") else ""))
    print(f"Full result: {args.output}")

    if failed:
        fail("ANTI_FAKE_CHECK_FAILED", f"client-side checks did not pass: {', '.join(failed)}")
        return 1
    print("[OK] node returned real-hardware assurance bound to our nonce")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
