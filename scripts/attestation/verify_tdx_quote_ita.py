#!/usr/bin/env python3
"""Verify TDX quote externally using Intel Trust Authority.

Inputs:
  - attestation response JSON (from /admin-api/tee/attest)
  - tee info JSON (from /admin-api/tee/info), optional for MRTD cross-check
  - ITA API key and appraisal endpoint

Outputs (written under output-dir):
  - external-verification-attempts.json
  - external-verification-request.json
  - external-verification-response.json
  - external-attestation-token.jwt
  - external-attestation-token-claims.json
  - mrtd.json
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Tuple


QUOTE_KEY_HINTS = {
    "quote",
    "raw_quote",
    "quote_b64",
    "quote_base64",
    "quotebase64",
    "quotebytes",
    "tdx_quote",
}

TOKEN_KEY_HINTS = {
    "token",
    "attestation_token",
    "jwt",
    "signed_token",
}

MRTD_KEY_HINTS = {
    "mrtd",
    "tdx_mrtd",
    "mr_td",
    "mrtd_hex",
}

BASE64_CANDIDATE_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")
HEX_RE = re.compile(r"^[A-Fa-f0-9]{32,}$")


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, payload: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")


def walk_json(value: Any, path: str = "$") -> Iterable[Tuple[str, Any]]:
    yield path, value
    if isinstance(value, dict):
        for k, v in value.items():
            child_path = f"{path}.{k}"
            yield from walk_json(v, child_path)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            child_path = f"{path}[{i}]"
            yield from walk_json(v, child_path)


def decode_base64_flexible(value: str) -> Optional[bytes]:
    cleaned = value.strip()
    if not cleaned:
        return None
    if not BASE64_CANDIDATE_RE.match(cleaned):
        return None

    padded = cleaned + ("=" * ((4 - (len(cleaned) % 4)) % 4))
    try:
        return base64.b64decode(padded, validate=False)
    except Exception:
        return None


def looks_like_quote_b64(value: str) -> bool:
    decoded = decode_base64_flexible(value)
    if decoded is None:
        return False
    # TDX quotes are binary blobs and are typically >1KB.
    return len(decoded) > 300


def extract_best_quote(attestation_response: Any) -> Tuple[str, str]:
    candidates: List[Tuple[int, int, str, str]] = []

    for path, value in walk_json(attestation_response):
        if not isinstance(value, str):
            continue
        key = path.split(".")[-1].lower().strip("[]0123456789")
        score = 0

        if key in QUOTE_KEY_HINTS:
            score += 10
        if "quote" in key:
            score += 5
        if looks_like_quote_b64(value):
            score += 3

        if score > 0:
            candidates.append((score, len(value), value, path))

    if not candidates:
        raise RuntimeError("Could not find any quote-like field in attestation response JSON")

    best = sorted(candidates, key=lambda x: (x[0], x[1]), reverse=True)[0]
    return best[2], best[3]


def parse_policy_ids(raw: str) -> List[str]:
    ids = [p.strip() for p in raw.split(",")]
    return [p for p in ids if p]


def post_json(url: str, api_key: str, payload: Dict[str, Any], timeout: int = 60) -> Tuple[int, Dict[str, str], str]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url=url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    req.add_header("x-api-key", api_key)
    req.add_header("api-key", api_key)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers.items()), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return e.code, dict(e.headers.items()), body


def looks_like_jwt(value: str) -> bool:
    candidate = value.strip()
    if candidate.lower().startswith("bearer "):
        candidate = candidate.split(" ", 1)[1].strip()
    parts = candidate.split(".")
    return len(parts) == 3 and all(parts)


def find_token(payload: Any) -> Optional[Tuple[str, str]]:
    if isinstance(payload, str):
        if looks_like_jwt(payload):
            token = payload.strip()
            if token.lower().startswith("bearer "):
                token = token.split(" ", 1)[1].strip()
            return token, "$"
        return None

    token_candidates: List[Tuple[int, int, str, str]] = []
    for path, value in walk_json(payload):
        if not isinstance(value, str):
            continue
        if not looks_like_jwt(value):
            continue
        key = path.split(".")[-1].lower().strip("[]0123456789")
        score = 1
        if key in TOKEN_KEY_HINTS:
            score += 5
        if "token" in key or "jwt" in key:
            score += 3
        token_candidates.append((score, len(value), value, path))

    if not token_candidates:
        return None
    best = sorted(token_candidates, key=lambda x: (x[0], x[1]), reverse=True)[0]
    token = best[2].strip()
    if token.lower().startswith("bearer "):
        token = token.split(" ", 1)[1].strip()
    return token, best[3]


def decode_jwt_claims(token: str) -> Dict[str, Any]:
    try:
        _, payload_b64, _ = token.split(".", 2)
    except ValueError as exc:
        raise RuntimeError("Invalid JWT format") from exc

    padded = payload_b64 + ("=" * ((4 - (len(payload_b64) % 4)) % 4))
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("utf-8"))
        return json.loads(decoded.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError("Failed to decode JWT payload") from exc


def find_mrtd(payload: Any) -> Optional[Tuple[str, str]]:
    candidates: List[Tuple[int, str, str]] = []

    for path, value in walk_json(payload):
        if not isinstance(value, str):
            continue
        key = path.split(".")[-1].lower().strip("[]0123456789")
        score = 0
        if key in MRTD_KEY_HINTS:
            score += 10
        if "mrtd" in key or "mr_td" in key:
            score += 5
        if HEX_RE.match(value):
            score += 2
        if score > 0:
            candidates.append((score, value, path))

    if not candidates:
        return None
    best = sorted(candidates, key=lambda x: (x[0], len(x[1])), reverse=True)[0]
    return best[1], best[2]


def normalize_hex(value: str) -> str:
    return value.lower().strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="External TDX quote verification via Intel Trust Authority")
    parser.add_argument("--attest-response", required=True, help="Path to tee-attest-response.json")
    parser.add_argument("--tee-info", required=False, help="Path to tee-info.json")
    parser.add_argument("--output-dir", required=True, help="Directory for verification artifacts")
    parser.add_argument(
        "--ita-url",
        default="https://api.trustauthority.intel.com/appraisal/v2/attest",
        help="Intel Trust Authority appraisal endpoint",
    )
    parser.add_argument("--ita-api-key", required=True, help="Intel Trust Authority API key")
    parser.add_argument("--policy-ids", default="", help="Comma-separated policy UUID list")
    parser.add_argument(
        "--policy-must-match",
        action="store_true",
        help="Require policy match when policy IDs are supplied",
    )
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    attest_payload = load_json(args.attest_response)
    quote_b64, quote_path = extract_best_quote(attest_payload)

    policy_ids = parse_policy_ids(args.policy_ids)
    request_payload: Dict[str, Any] = {"tdx": {"quote": quote_b64}}
    if policy_ids:
        request_payload["policy_ids"] = policy_ids
        request_payload["policy_must_match"] = bool(args.policy_must_match)

    attempts: List[Dict[str, Any]] = []
    candidate_payloads = [
        ("v2_tdx", request_payload),
        ("legacy_quote", {"quote": quote_b64}),
    ]

    candidate_urls = [args.ita_url]
    if "/v2/" in args.ita_url:
        candidate_urls.append(args.ita_url.replace("/v2/", "/v1/"))

    chosen_response: Optional[Dict[str, Any]] = None
    chosen_request: Optional[Dict[str, Any]] = None

    for url in candidate_urls:
        for request_kind, payload in candidate_payloads:
            status, headers, body = post_json(url=url, api_key=args.ita_api_key, payload=payload)
            attempt = {
                "timestamp_utc": dt.datetime.utcnow().isoformat() + "Z",
                "url": url,
                "request_kind": request_kind,
                "status": status,
                "headers": headers,
                "body_preview": body[:2000],
            }
            attempts.append(attempt)

            if 200 <= status < 300:
                chosen_response = {
                    "status": status,
                    "headers": headers,
                    "body": body,
                    "url": url,
                    "request_kind": request_kind,
                }
                chosen_request = payload
                break
        if chosen_response is not None:
            break

    save_json(os.path.join(args.output_dir, "external-verification-attempts.json"), attempts)

    if chosen_response is None or chosen_request is None:
        raise RuntimeError("External quote verification failed: no successful ITA attestation response")

    save_json(os.path.join(args.output_dir, "external-verification-request.json"), chosen_request)

    response_body = chosen_response["body"]
    try:
        parsed_response = json.loads(response_body)
    except json.JSONDecodeError:
        parsed_response = {"raw_response": response_body}

    save_json(os.path.join(args.output_dir, "external-verification-response.json"), parsed_response)

    token_info = find_token(parsed_response)
    if token_info is None:
        raise RuntimeError("Could not locate JWT attestation token in ITA response")

    token, token_path = token_info
    with open(os.path.join(args.output_dir, "external-attestation-token.jwt"), "w", encoding="utf-8") as f:
        f.write(token)
        f.write("\n")

    claims = decode_jwt_claims(token)
    save_json(os.path.join(args.output_dir, "external-attestation-token-claims.json"), claims)

    mrtd_info = find_mrtd(claims)
    if mrtd_info is None:
        raise RuntimeError("Could not extract MRTD from external attestation token claims")
    mrtd_value, mrtd_path = mrtd_info

    tee_info_mrtd = None
    tee_info_path = None
    if args.tee_info and os.path.exists(args.tee_info):
        tee_info_payload = load_json(args.tee_info)
        tee_mrtd_info = find_mrtd(tee_info_payload)
        if tee_mrtd_info is not None:
            tee_info_mrtd, tee_info_path = tee_mrtd_info

    mrtd_payload = {
        "mrtd": mrtd_value,
        "mrtd_source": "external_attestation_token",
        "mrtd_path": mrtd_path,
        "quote_path": quote_path,
        "token_path": token_path,
        "ita_url": chosen_response["url"],
        "ita_request_kind": chosen_response["request_kind"],
        "timestamp_utc": dt.datetime.utcnow().isoformat() + "Z",
    }

    if tee_info_mrtd is not None:
        mrtd_payload["tee_info_mrtd"] = tee_info_mrtd
        mrtd_payload["tee_info_mrtd_path"] = tee_info_path
        if normalize_hex(tee_info_mrtd) != normalize_hex(mrtd_value):
            save_json(os.path.join(args.output_dir, "mrtd.json"), mrtd_payload)
            raise RuntimeError("MRTD mismatch between tee-info and external attestation token")

    save_json(os.path.join(args.output_dir, "mrtd.json"), mrtd_payload)

    print(f"MRTD={mrtd_value}")
    print(f"MRTD_PATH={mrtd_path}")
    print(f"QUOTE_PATH={quote_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
