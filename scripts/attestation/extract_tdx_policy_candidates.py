#!/usr/bin/env python3
"""Extract KMS policy candidate values from ITA attestation token claims.

MRTD and RTMR0–3 are taken from **merod** ``data.quote.body`` when present (same as
``tdx_quote`` / KMS quote-first behaviour); otherwise from ``data.quoteB64`` bytes
(same layout as ``attestation-verifier`` ``extractMeasurementsFromQuoteB64``).

TCB status strings still come from ITA token claims (not present as plain text in the
quote blob we parse here).

This helper reads ``external-attestation-token-claims.json`` produced by
``scripts/attestation/verify_tdx_quote_ita.py`` and derives candidate values for:

  - MERO_KMS_ALLOWED_TCB_STATUSES_JSON
  - MERO_KMS_ALLOWED_MRTD_JSON
  - MERO_KMS_ALLOWED_RTMR0_JSON
  - MERO_KMS_ALLOWED_RTMR1_JSON
  - MERO_KMS_ALLOWED_RTMR2_JSON
  - MERO_KMS_ALLOWED_RTMR3_JSON
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple


HEX_48_RE = re.compile(r"^(?:0x)?([A-Fa-f0-9]{96})$")

BASE64_CANDIDATE_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")

# TDX quote binary layout (Intel TDX DCAP) — keep in sync with attestation.js
MRTD_LEN = 48
MRTD_OFFSET_V4 = 184
MRTD_OFFSET_V5 = 190
RTMR0_OFFSET_FROM_MRTD = 192


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


def walk_json(value: Any, path: str = "$") -> Iterable[Tuple[str, Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk_json(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_json(child, f"{path}[{index}]")


def _norm_hex_96(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    s = value.strip().lower().replace("0x", "")
    if len(s) == 96 and all(c in "0123456789abcdef" for c in s):
        return s
    return None


def _measurements_from_merod_quote_body(attest_payload: Any) -> Optional[Dict[str, str]]:
    """MRTD and RTMR0–3 from ``data.quote.body`` (merod /admin-api/tee/attest)."""
    if not isinstance(attest_payload, dict):
        return None
    data = attest_payload.get("data")
    if not isinstance(data, dict):
        return None
    quote = data.get("quote")
    if not isinstance(quote, dict):
        return None
    body = quote.get("body")
    if not isinstance(body, dict):
        return None
    out: Dict[str, str] = {}
    for k in ("mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"):
        h = _norm_hex_96(body.get(k))
        if h:
            out[k] = h
    return out if out else None


def _quote_b64_from_merod_attest(attest_payload: Any) -> Tuple[Optional[str], str]:
    """Canonical ``data.quoteB64`` from merod tee/attest JSON."""
    if not isinstance(attest_payload, dict):
        return None, ""
    data = attest_payload.get("data")
    if not isinstance(data, dict):
        return None, ""
    for key in ("quoteB64", "quote_b64"):
        raw = data.get(key)
        if isinstance(raw, str) and raw.strip():
            return raw.strip(), f"$.data.{key}"
    return None, ""


def _hex48(data: bytes) -> str:
    return data.hex()


def extract_measurements_from_quote_bytes(data: bytes) -> Optional[Dict[str, str]]:
    """Return mrtd, rtmr0..3 as 96-char lowercase hex, or None if layout unsupported."""
    if len(data) < MRTD_LEN:
        return None
    version = data[0] | (data[1] << 8)
    if version == 4:
        mrtd_offset = MRTD_OFFSET_V4
    elif version == 5:
        mrtd_offset = MRTD_OFFSET_V5
    else:
        return None
    if mrtd_offset + MRTD_LEN > len(data):
        return None
    rtmr0_off = mrtd_offset + RTMR0_OFFSET_FROM_MRTD
    if rtmr0_off + MRTD_LEN * 4 > len(data):
        return None
    out: Dict[str, str] = {
        "mrtd": _hex48(data[mrtd_offset : mrtd_offset + MRTD_LEN]),
    }
    for i in range(4):
        off = rtmr0_off + i * MRTD_LEN
        out[f"rtmr{i}"] = _hex48(data[off : off + MRTD_LEN])
    return out


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def save_json(path: str, payload: Any) -> None:
    with open(path, "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, sort_keys=True)
        file.write("\n")


def normalize_measurement(value: str) -> Optional[str]:
    candidate = value.strip()
    match = HEX_48_RE.match(candidate)
    if not match:
        return None
    return match.group(1).lower()


def normalize_key_segment(path: str) -> str:
    key = path.split(".")[-1]
    key = re.sub(r"\[[0-9]+\]", "", key)
    return re.sub(r"[^a-z0-9]", "", key.lower())


def normalize_tcb_status(raw: str) -> Optional[str]:
    token = re.sub(r"[^a-z0-9]", "", raw.strip().lower())
    if not token:
        return None

    aliases = {
        "uptodate": "uptodate",
        "up2date": "uptodate",
        "outofdate": "outofdate",
        "revoked": "revoked",
        "configurationandswhardeningneeded": "configurationandswhardeningneeded",
        "configurationneeded": "configurationneeded",
        "swhardeningneeded": "swhardeningneeded",
        "unrecognized": "unrecognized",
    }
    return aliases.get(token, token)


def extract_measurement_from_claims_canonical(
    payload: Any, target: str
) -> Optional[Tuple[str, str]]:
    """Pick MRTD/RTMR from ITA JWT claims using only canonical Intel field names.

    Used when ``--attest-response`` is not passed. Prefer passing ``--attest-response`` so
    measurements come from the parsed TD quote (ground truth)."""
    preferred_keys = {
        "mrtd": ("tdx_mrtd", "mr_td", "mrtd"),
        "rtmr0": ("tdx_rtmr0",),
        "rtmr1": ("tdx_rtmr1",),
        "rtmr2": ("tdx_rtmr2",),
        "rtmr3": ("tdx_rtmr3",),
    }
    if target not in preferred_keys:
        return None
    want: Tuple[str, ...] = preferred_keys[target]
    for path, value in walk_json(payload):
        if not isinstance(value, str):
            continue
        key_norm = normalize_key_segment(path)
        for pk in want:
            if key_norm == re.sub(r"[^a-z0-9]", "", pk.lower()):
                measurement = normalize_measurement(value)
                if measurement is not None:
                    return measurement, path
    return None


def measurements_from_quote(attest_payload: Any) -> Tuple[Dict[str, Tuple[str, str]], str]:
    """Return per-target (hex, path) entries and the source path (merod body or quoteB64)."""
    body_meas = _measurements_from_merod_quote_body(attest_payload)
    if body_meas and body_meas.get("mrtd") and all(body_meas.get(f"rtmr{i}") for i in range(4)):
        bm = body_meas
        label = "quote:$.data.quote.body"
        out: Dict[str, Tuple[str, str]] = {"mrtd": (bm["mrtd"], label)}
        for i in range(4):
            k = f"rtmr{i}"
            out[k] = (bm[k], label)
        return out, "$.data.quote.body"

    quote_b64, field_path = _quote_b64_from_merod_attest(attest_payload)
    if not quote_b64:
        raise RuntimeError(
            "Attest JSON missing data.quote.body measurements and data.quoteB64; "
            "expected merod /admin-api/tee/attest shape"
        )
    raw = decode_base64_flexible(quote_b64)
    if raw is None:
        raise RuntimeError("Could not base64-decode data.quoteB64")
    parsed = extract_measurements_from_quote_bytes(raw)
    if parsed is None:
        raise RuntimeError(
            "Could not parse MRTD/RTMR from TD quote (expected quote version 4 or 5)"
        )
    label = f"quote:{field_path}"
    out = {
        "mrtd": (parsed["mrtd"], label),
    }
    for i in range(4):
        out[f"rtmr{i}"] = (parsed[f"rtmr{i}"], label)
    return out, field_path


def extract_tcb_status_candidates(payload: Any) -> List[Tuple[str, str, str]]:
    """TCB status strings from ITA claims: fixed key names first, then deterministic path order (no scoring)."""
    if isinstance(payload, dict):
        for key in (
            "attester_tcb_status",
            "attesterTcbStatus",
            "tcb_status",
            "tcbStatus",
        ):
            v = payload.get(key)
            if isinstance(v, str):
                ns = normalize_tcb_status(v)
                if ns is not None:
                    return [(ns, f"$.{key}", v)]

    rows: List[Tuple[str, str, str, str]] = []
    for path, value in walk_json(payload):
        if not isinstance(value, str):
            continue
        normalized_status = normalize_tcb_status(value)
        if normalized_status is None:
            continue
        key_norm = normalize_key_segment(path)
        path_norm = re.sub(r"[^a-z0-9]", "", path.lower())
        if key_norm in {"tcbstatus", "attestertcbstatus"}:
            rows.append((path, normalized_status, path, value))
        elif "tcb" in key_norm and "status" in key_norm:
            rows.append((path, normalized_status, path, value))
        elif "tcb" in path_norm and "status" in path_norm:
            rows.append((path, normalized_status, path, value))

    rows.sort(key=lambda x: x[0])
    seen: set[str] = set()
    out: List[Tuple[str, str, str]] = []
    for _, normalized_status, path, raw in rows:
        if normalized_status in seen:
            continue
        seen.add(normalized_status)
        out.append((normalized_status, path, raw))
    return out


def compact_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract MERO_KMS_ALLOWED_*_JSON candidates from ITA token claims"
    )
    parser.add_argument("--claims", required=True, help="Path to token claims JSON")
    parser.add_argument(
        "--attest-response",
        required=False,
        help=(
            "Path to tee/attest JSON (same as verify_tdx_quote_ita.py). When set, MRTD and "
            "RTMR0–3 are read from the TD quote binary (recommended); claims are not used for "
            "those fields."
        ),
    )
    parser.add_argument("--output-json", required=True, help="Output JSON summary path")
    parser.add_argument(
        "--output-env",
        required=False,
        help="Optional output env file path with MERO_KMS_ALLOWED_*_JSON entries",
    )
    parser.add_argument(
        "--allow-missing-tcb",
        action="store_true",
        help="Do not fail if no TCB status claim is found",
    )
    parser.add_argument(
        "--allow-missing-mrtd",
        action="store_true",
        help="Do not fail if no MRTD claim is found",
    )
    args = parser.parse_args()

    claims = load_json(args.claims)

    measurement_source: str
    quote_field_path: Optional[str] = None
    if args.attest_response:
        attest_payload = load_json(args.attest_response)
        from_quote, quote_field_path = measurements_from_quote(attest_payload)
        mrtd = from_quote["mrtd"]
        rtmr0 = from_quote["rtmr0"]
        rtmr1 = from_quote["rtmr1"]
        rtmr2 = from_quote["rtmr2"]
        rtmr3 = from_quote["rtmr3"]
        measurement_source = "td_quote"
    else:
        mrtd = extract_measurement_from_claims_canonical(claims, "mrtd")
        rtmr0 = extract_measurement_from_claims_canonical(claims, "rtmr0")
        rtmr1 = extract_measurement_from_claims_canonical(claims, "rtmr1")
        rtmr2 = extract_measurement_from_claims_canonical(claims, "rtmr2")
        rtmr3 = extract_measurement_from_claims_canonical(claims, "rtmr3")
        measurement_source = "ita_claims_canonical"
    tcb_candidates = extract_tcb_status_candidates(claims)

    if mrtd is None and not args.allow_missing_mrtd:
        hint = (
            " Pass --attest-response with the same JSON used for verify_tdx_quote_ita.py "
            "to derive MRTD/RTMR from the TD quote."
        )
        raise RuntimeError(
            "Could not extract MRTD; refusing to generate candidate policy." + hint
        )
    if not tcb_candidates and not args.allow_missing_tcb:
        raise RuntimeError(
            "Could not extract attester TCB status from token claims; refusing to generate candidate policy."
        )

    allowed_tcb_statuses = [value for value, _, _ in tcb_candidates]
    allowed_mrtd = [mrtd[0]] if mrtd is not None else []
    allowed_rtmr0 = [rtmr0[0]] if rtmr0 is not None else []
    allowed_rtmr1 = [rtmr1[0]] if rtmr1 is not None else []
    allowed_rtmr2 = [rtmr2[0]] if rtmr2 is not None else []
    allowed_rtmr3 = [rtmr3[0]] if rtmr3 is not None else []

    output = {
        "schema_version": 1,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "measurement_source": measurement_source,
        "source_attest_response_path": args.attest_response,
        "quote_field_path": quote_field_path,
        "source_claims_path": args.claims,
        "source_claim_paths": {
            "mrtd": mrtd[1] if mrtd is not None else None,
            "rtmr0": rtmr0[1] if rtmr0 is not None else None,
            "rtmr1": rtmr1[1] if rtmr1 is not None else None,
            "rtmr2": rtmr2[1] if rtmr2 is not None else None,
            "rtmr3": rtmr3[1] if rtmr3 is not None else None,
            "tcb_statuses": [
                {"value": value, "path": path, "raw": raw}
                for value, path, raw in tcb_candidates
            ],
        },
        "policy": {
            "allowed_tcb_statuses": allowed_tcb_statuses,
            "allowed_mrtd": allowed_mrtd,
            "allowed_rtmr0": allowed_rtmr0,
            "allowed_rtmr1": allowed_rtmr1,
            "allowed_rtmr2": allowed_rtmr2,
            "allowed_rtmr3": allowed_rtmr3,
        },
        "github_repository_variables": {
            "MERO_KMS_ALLOWED_TCB_STATUSES_JSON": compact_json(allowed_tcb_statuses),
            "MERO_KMS_ALLOWED_MRTD_JSON": compact_json(allowed_mrtd),
            "MERO_KMS_ALLOWED_RTMR0_JSON": compact_json(allowed_rtmr0),
            "MERO_KMS_ALLOWED_RTMR1_JSON": compact_json(allowed_rtmr1),
            "MERO_KMS_ALLOWED_RTMR2_JSON": compact_json(allowed_rtmr2),
            "MERO_KMS_ALLOWED_RTMR3_JSON": compact_json(allowed_rtmr3),
        },
    }
    save_json(args.output_json, output)

    if args.output_env:
        with open(args.output_env, "w", encoding="utf-8") as env_file:
            for key, value in output["github_repository_variables"].items():
                env_file.write(f"{key}={value}\n")

    for key, value in output["github_repository_variables"].items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
