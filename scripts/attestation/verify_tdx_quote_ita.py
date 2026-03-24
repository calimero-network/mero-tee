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
  - ita-ci-verification-summary.json (human-readable fields for CI logs / artifacts)
  - mrtd.json
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Tuple

from extract_tdx_policy_candidates import measurements_from_quote


MRTD_KEY_HINTS = frozenset(
    {
        "mrtd",
        "tdx_mrtd",
        "mr_td",
        "mrtd_hex",
    }
)

# Intel Trust Authority HTTP JSON: try these before any tree walk (deterministic).
ITA_JWT_PATHS: Tuple[Tuple[str, ...], ...] = (
    ("token",),
    ("attestationToken",),
    ("attestation_token",),
    ("jwt",),
    ("signed_token",),
    ("signedToken",),
    ("data", "token"),
    ("data", "attestationToken"),
    ("data", "attestation_token"),
    ("result", "token"),
    ("response", "token"),
)

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


def quote_b64_from_attest_json(attestation_response: Any) -> Tuple[str, str]:
    """TD quote base64: merod ``data.quoteB64`` or mero-kms ``/attest`` top-level ``quoteB64``."""
    if not isinstance(attestation_response, dict):
        raise RuntimeError("Attest response must be a JSON object")
    data = attestation_response.get("data")
    if isinstance(data, dict):
        for key in ("quoteB64", "quote_b64"):
            raw = data.get(key)
            if isinstance(raw, str) and raw.strip():
                return raw.strip(), f"$.data.{key}"
    for key in ("quoteB64", "quote_b64"):
        raw = attestation_response.get(key)
        if isinstance(raw, str) and raw.strip():
            return raw.strip(), f"$.{key}"
    raise RuntimeError(
        "Attest response missing quote base64: expected merod data.quoteB64 or mero-kms quoteB64 (top-level)"
    )


def parse_policy_ids(raw: str) -> List[str]:
    ids = [p.strip() for p in raw.split(",")]
    return [p for p in ids if p]


RETRYABLE_HTTP_STATUS_CODES = {429, 500, 502, 503, 504}


def post_json(
    url: str,
    api_key: str,
    payload: Dict[str, Any],
    timeout: int = 60,
    network_retries: int = 3,
    network_backoff_seconds: int = 2,
) -> Tuple[int, Dict[str, str], str]:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url=url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    req.add_header("x-api-key", api_key)
    req.add_header("api-key", api_key)

    attempts = max(1, int(network_retries))
    backoff = max(1, int(network_backoff_seconds))
    last_transport_error = ""

    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, dict(resp.headers.items()), resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            if e.code in RETRYABLE_HTTP_STATUS_CODES and attempt < attempts:
                time.sleep(backoff * (2 ** (attempt - 1)))
                continue
            return e.code, dict(e.headers.items()), body
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            last_transport_error = str(e)
            if attempt < attempts:
                time.sleep(backoff * (2 ** (attempt - 1)))
                continue

    return 0, {}, f"transport_error_after_retries: {last_transport_error or 'unknown transport error'}"


def looks_like_jwt(value: str) -> bool:
    candidate = value.strip()
    if candidate.lower().startswith("bearer "):
        candidate = candidate.split(" ", 1)[1].strip()
    parts = candidate.split(".")
    return len(parts) == 3 and all(parts)


def _strip_bearer_jwt(value: str) -> str:
    token = value.strip()
    if token.lower().startswith("bearer "):
        token = token.split(" ", 1)[1].strip()
    return token


def _get_at_path(obj: Any, parts: Tuple[str, ...]) -> Any:
    cur: Any = obj
    for p in parts:
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def find_token(payload: Any) -> Optional[Tuple[str, str]]:
    """JWT from ITA response: fixed paths first, else lexicographically first JWT in tree (no scoring)."""
    if isinstance(payload, str):
        if looks_like_jwt(payload):
            return _strip_bearer_jwt(payload), "$"
        return None

    if isinstance(payload, dict):
        for parts in ITA_JWT_PATHS:
            v = _get_at_path(payload, parts)
            if isinstance(v, str) and looks_like_jwt(v):
                path_str = "$." + ".".join(parts)
                return _strip_bearer_jwt(v), path_str

    jwt_at_paths: List[Tuple[str, str]] = []
    for path, value in walk_json(payload):
        if isinstance(value, str) and looks_like_jwt(value):
            jwt_at_paths.append((path, _strip_bearer_jwt(value)))
    if not jwt_at_paths:
        return None
    path, token = sorted(jwt_at_paths, key=lambda x: x[0])[0]
    return token, path


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


def _mrtd_key_segment(path: str) -> str:
    key = path.split(".")[-1]
    key = re.sub(r"\[[0-9]+\]", "", key)
    return re.sub(r"[^a-z0-9]", "", key.lower())


def find_mrtd(payload: Any) -> Optional[Tuple[str, str]]:
    """MRTD hex for tee-info (merod ``data.mrtd``) or ITA claims (``tdx_mrtd`` / …). No scoring."""
    if not isinstance(payload, dict):
        return None
    # merod /admin-api/tee/info
    data = payload.get("data")
    if isinstance(data, dict):
        v = data.get("mrtd")
        if isinstance(v, str) and HEX_RE.match(v.replace("0x", "").replace("0X", "")):
            return v, "$.data.mrtd"
    for key in ("tdx_mrtd", "mr_td", "mrtd", "mrtd_hex"):
        v = payload.get(key)
        if isinstance(v, str) and HEX_RE.match(v.replace("0x", "").replace("0X", "")):
            return v, f"$.{key}"

    matches: List[Tuple[str, str]] = []
    for path, value in walk_json(payload):
        if not isinstance(value, str):
            continue
        if not HEX_RE.match(value.replace("0x", "").replace("0X", "")):
            continue
        seg = _mrtd_key_segment(path)
        if seg in MRTD_KEY_HINTS:
            matches.append((path, value))
    if not matches:
        return None
    path, value = sorted(matches, key=lambda x: x[0])[0]
    return value, path


def normalize_hex(value: str) -> str:
    return value.lower().strip()


def resolve_mrtd(
    claims: Any,
    attest_payload: Any,
) -> Tuple[str, str, str]:
    """ITA JWT MRTD when present; else MRTD parsed from TD quote (v4/v5 layout).

    If both are present, they must agree (hex-normalized).
    Returns (mrtd_hex, path_description, source) where source is
    ``external_attestation_token``, ``parsed_td_quote``, or ``ita_and_quote`` when both matched.
    """
    claim_mrtd = find_mrtd(claims)
    quote_mrtd: Optional[Tuple[str, str]] = None
    try:
        meas, _field = measurements_from_quote(attest_payload)
        quote_mrtd = meas["mrtd"]
    except RuntimeError:
        pass

    if claim_mrtd is not None and quote_mrtd is not None:
        cv, cp = claim_mrtd
        qv, qp = quote_mrtd
        if normalize_hex(cv) != normalize_hex(qv):
            raise RuntimeError(
                "MRTD mismatch between ITA JWT claims and measurements parsed from TD quote "
                f"(claims {cp} vs quote {qp})"
            )
        return cv, cp, "ita_and_quote"

    if claim_mrtd is not None:
        v, p = claim_mrtd
        return v, p, "external_attestation_token"

    if quote_mrtd is not None:
        v, p = quote_mrtd
        return v, p, "parsed_td_quote"

    raise RuntimeError(
        "Could not extract MRTD from ITA claims or from TD quote bytes "
        "(expected ITA mrtd/mr_td-style fields or merod/KMS quoteB64 / data.quote.body)"
    )


def write_ci_verification_summary(
    *,
    output_dir: str,
    ita_url: str,
    ita_request_kind: str,
    quote_path: str,
    quote_b64: str,
    claims: Any,
    token_path: str,
) -> None:
    """Print and save a bounded summary for GitHub Actions (no raw quote base64)."""
    quote_bytes = decode_base64_flexible(quote_b64) or b""
    quote_sha256 = hashlib.sha256(quote_bytes).hexdigest() if quote_bytes else ""

    top_keys = list(claims.keys()) if isinstance(claims, dict) else []

    summary: Dict[str, Any] = {
        "ita_url": ita_url,
        "ita_request_kind": ita_request_kind,
        "node_attest_response_quote_json_path": quote_path,
        "node_quote_b64_character_count": len(quote_b64),
        "node_quote_sha256_hex": quote_sha256,
        "ita_jwt_token_json_path": token_path,
        "ita_jwt_claim_top_level_keys": top_keys,
        "note": "MRTD/RTMR ground truth: merod data.quote.body / data.quoteB64; see external-attestation-token-claims.json for full ITA JWT.",
    }

    path = os.path.join(output_dir, "ita-ci-verification-summary.json")
    save_json(path, summary)

    print("")
    print("=== ITA verification — CI summary (Intel Trust Authority) ===")
    print(f"ita_url={ita_url}")
    print(f"ita_request_kind={ita_request_kind}")
    print(f"node_quote_json_path={quote_path}")
    print(f"node_quote_b64_length={len(quote_b64)}")
    print(f"node_quote_sha256={quote_sha256}")
    print(f"ita_jwt_token_path={token_path}")
    print(f"ita_jwt_claim_top_level_keys={top_keys}")
    print("MRTD/RTMR: use merod attest JSON (data.quote.body); ITA claims in external-attestation-token-claims.json")
    print(f"Full JSON: {path}")
    print("=== End ITA CI summary ===")
    print("")


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
    parser.add_argument(
        "--ita-network-retries",
        type=int,
        default=3,
        help="Number of retry attempts for transient ITA HTTP/network failures",
    )
    parser.add_argument(
        "--ita-network-backoff-seconds",
        type=int,
        default=2,
        help="Base exponential backoff in seconds for ITA request retries",
    )
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    attest_payload = load_json(args.attest_response)
    quote_b64, quote_path = quote_b64_from_attest_json(attest_payload)

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
            status, headers, body = post_json(
                url=url,
                api_key=args.ita_api_key,
                payload=payload,
                network_retries=args.ita_network_retries,
                network_backoff_seconds=args.ita_network_backoff_seconds,
            )
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

    write_ci_verification_summary(
        output_dir=args.output_dir,
        ita_url=str(chosen_response["url"]),
        ita_request_kind=str(chosen_response["request_kind"]),
        quote_path=quote_path,
        quote_b64=quote_b64,
        claims=claims,
        token_path=token_path,
    )

    mrtd_value, mrtd_path, mrtd_source = resolve_mrtd(claims, attest_payload)

    tee_info_mrtd = None
    tee_info_path = None
    if args.tee_info and os.path.exists(args.tee_info):
        tee_info_payload = load_json(args.tee_info)
        tee_mrtd_info = find_mrtd(tee_info_payload)
        if tee_mrtd_info is not None:
            tee_info_mrtd, tee_info_path = tee_mrtd_info

    mrtd_payload = {
        "mrtd": mrtd_value,
        "mrtd_source": mrtd_source,
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
            raise RuntimeError("MRTD mismatch between tee-info and resolved attestation MRTD")

    save_json(os.path.join(args.output_dir, "mrtd.json"), mrtd_payload)

    print(f"MRTD={mrtd_value}")
    print(f"MRTD_PATH={mrtd_path}")
    print(f"QUOTE_PATH={quote_path}")
    print("(See ITA CI summary above for ITA JWT tdx_* fields and node quote SHA-256.)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover
        print(f"ERROR: {exc}", file=sys.stderr)
        raise
