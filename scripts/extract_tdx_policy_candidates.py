#!/usr/bin/env python3
"""Extract KMS policy candidate values from ITA attestation token claims.

This helper reads `external-attestation-token-claims.json` produced by
`scripts/verify_tdx_quote_ita.py` and derives candidate values for:

  - MERO_KMS_ALLOWED_TCB_STATUSES_JSON
  - MERO_KMS_ALLOWED_MRTD_JSON
  - MERO_KMS_ALLOWED_RTMR0_JSON
  - MERO_KMS_ALLOWED_RTMR1_JSON
  - MERO_KMS_ALLOWED_RTMR2_JSON
  - MERO_KMS_ALLOWED_RTMR3_JSON
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple


HEX_48_RE = re.compile(r"^(?:0x)?([A-Fa-f0-9]{96})$")


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def save_json(path: str, payload: Any) -> None:
    with open(path, "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2, sort_keys=True)
        file.write("\n")


def walk_json(value: Any, path: str = "$") -> Iterable[Tuple[str, Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk_json(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_json(child, f"{path}[{index}]")


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


def score_measurement_path(target: str, path: str) -> int:
    target_norm = target.lower()
    key_norm = normalize_key_segment(path)
    path_norm = re.sub(r"[^a-z0-9]", "", path.lower())
    score = 0

    if key_norm == target_norm:
        score += 30
    if key_norm == f"tdx{target_norm}":
        score += 25
    if key_norm.endswith(target_norm):
        score += 15
    if target_norm in key_norm:
        score += 10
    if target_norm in path_norm:
        score += 6
    if "tdx" in key_norm:
        score += 3
    return score


def extract_best_measurement(payload: Any, target: str) -> Optional[Tuple[str, str]]:
    candidates: List[Tuple[int, str, str]] = []
    for path, value in walk_json(payload):
        if not isinstance(value, str):
            continue
        measurement = normalize_measurement(value)
        if measurement is None:
            continue

        score = score_measurement_path(target, path)
        if score <= 0:
            continue
        candidates.append((score, measurement, path))

    if not candidates:
        return None
    score, measurement, path = sorted(
        candidates, key=lambda item: (item[0], len(item[2])), reverse=True
    )[0]
    _ = score
    return measurement, path


def extract_tcb_status_candidates(payload: Any) -> List[Tuple[str, str, str]]:
    candidates: List[Tuple[int, str, str, str]] = []
    for path, value in walk_json(payload):
        if not isinstance(value, str):
            continue

        normalized_status = normalize_tcb_status(value)
        if normalized_status is None:
            continue

        key_norm = normalize_key_segment(path)
        path_norm = re.sub(r"[^a-z0-9]", "", path.lower())
        score = 0

        if key_norm in {"tcbstatus", "attestertcbstatus"}:
            score += 30
        if "tcb" in key_norm and "status" in key_norm:
            score += 20
        if "tcb" in path_norm and "status" in path_norm:
            score += 12
        if path_norm.endswith("status"):
            score += 3

        if score > 0:
            candidates.append((score, normalized_status, path, value))

    candidates.sort(key=lambda item: (item[0], len(item[2])), reverse=True)

    unique_values: Dict[str, Tuple[str, str]] = {}
    for _, normalized_status, path, raw in candidates:
        if normalized_status in unique_values:
            continue
        unique_values[normalized_status] = (path, raw)

    return [
        (status, path, raw) for status, (path, raw) in unique_values.items()
    ]


def compact_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract MERO_KMS_ALLOWED_*_JSON candidates from ITA token claims"
    )
    parser.add_argument("--claims", required=True, help="Path to token claims JSON")
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

    mrtd = extract_best_measurement(claims, "mrtd")
    rtmr0 = extract_best_measurement(claims, "rtmr0")
    rtmr1 = extract_best_measurement(claims, "rtmr1")
    rtmr2 = extract_best_measurement(claims, "rtmr2")
    rtmr3 = extract_best_measurement(claims, "rtmr3")
    tcb_candidates = extract_tcb_status_candidates(claims)

    if mrtd is None and not args.allow_missing_mrtd:
        raise RuntimeError(
            "Could not extract MRTD from token claims; refusing to generate candidate policy."
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
