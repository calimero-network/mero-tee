#!/usr/bin/env python3
"""Provision CVM via Phala REST API with prefer_dev=False (dstack-0.5.7 prod).

Matches MDMA's phala_provider.provision_kms_deployment exactly: same API calls,
same base URL, same headers, same payload structure. Uses requests like MDMA.

Pinned via DSTACK_PREFER_DEV (default false). Env vars:
  PHALA_CLOUD_API_KEY (required)
  PHALA_API_BASE_URL or PHALA_CLOUD_API_PREFIX (default: https://cloud-api.phala.com/api/v1)
  PHALA_API_VERSION (default: 2026-01-21)

Usage:
  scripts/phala/provision_prod.py --name NAME --compose COMPOSE_FILE \\
    --instance-type tdx.small [--region REGION] [--output OUTPUT_JSON]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

import requests

# Match MDMA defaults
BASE_URL_DEFAULT = "https://cloud-api.phala.com/api/v1"
API_VERSION_DEFAULT = "2026-01-21"
DSTACK_PREFER_DEV_DEFAULT = False


def _log(msg: str) -> None:
    print(f"[provision_prod] {msg}", file=sys.stderr, flush=True)


def _base_url() -> str:
    return (
        os.environ.get("PHALA_API_BASE_URL")
        or os.environ.get("PHALA_CLOUD_API_PREFIX")
        or BASE_URL_DEFAULT
    ).rstrip("/")


def _headers(api_key: str) -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
        "X-Phala-Version": (os.environ.get("PHALA_API_VERSION") or API_VERSION_DEFAULT).strip(),
    }


def _request(
    method: str,
    path: str,
    api_key: str,
    payload: dict | None = None,
    timeout: int = 45,
) -> dict | None:
    url = f"{_base_url()}/{path.lstrip('/')}"
    _log(f"{method.upper()} {path} -> {url}")
    resp = requests.request(
        method.upper(),
        url,
        headers=_headers(api_key),
        json=payload,
        timeout=timeout,
    )
    _log(f"{method.upper()} {path} <- {resp.status_code}")
    if resp.status_code >= 400:
        detail = None
        try:
            body = resp.json()
            detail = body.get("detail") if isinstance(body, dict) else body
        except Exception:
            detail = resp.text
        raise RuntimeError(f"Phala API {method.upper()} {path} failed ({resp.status_code}): {detail}")
    if resp.status_code == 204 or not resp.content:
        return None
    return resp.json()


def main() -> int:
    parser = argparse.ArgumentParser(description="Provision CVM via Phala API (prefer_dev=False, matches MDMA)")
    parser.add_argument("--name", required=True, help="CVM name")
    parser.add_argument("--compose", required=True, help="Path to docker-compose file")
    parser.add_argument("--instance-type", default="tdx.small", help="Instance type")
    parser.add_argument("--region", default="", help="Optional region")
    parser.add_argument("--output", default="", help="Output JSON path (default: stdout)")
    args = parser.parse_args()

    api_key = (os.environ.get("PHALA_CLOUD_API_KEY") or "").strip()
    if not api_key:
        _log("PHALA_CLOUD_API_KEY is required")
        return 1

    prefer_dev = (
        os.environ.get("DSTACK_PREFER_DEV", str(DSTACK_PREFER_DEV_DEFAULT))
        .strip()
        .lower()
        in ("1", "true", "yes")
    )
    _log(f"Pinned dstack: prefer_dev={prefer_dev} (matches MDMA phala_dstack_prefer_dev)")

    compose_path = args.compose
    if not os.path.isfile(compose_path):
        _log(f"Compose file not found: {compose_path}")
        return 1

    compose_yaml = open(compose_path, encoding="utf-8").read()

    provision_payload: dict = {
        "name": args.name,
        "instance_type": args.instance_type,
        "kms": "PHALA",
        "prefer_dev": prefer_dev,
        "listed": False,
        "compose_file": {
            "name": "",
            "docker_compose_file": compose_yaml,
            "allowed_envs": [],
            "public_logs": True,
            "public_sysinfo": False,
        },
    }
    if args.region:
        provision_payload["region"] = args.region

    try:
        provision = _request("POST", "/cvms/provision", api_key, provision_payload) or {}
    except Exception as e:
        _log(f"Provision failed: {e}")
        return 1

    app_id = (provision.get("app_id") or "").strip()
    compose_hash = (provision.get("compose_hash") or "").strip()
    if not app_id or not compose_hash:
        _log(f"Provision response missing app_id/compose_hash: {provision}")
        return 1

    _log(f"Provision OK: app_id={app_id!r}")

    try:
        commit = _request(
            "POST",
            "/cvms",
            api_key,
            {"app_id": app_id, "compose_hash": compose_hash},
        ) or {}
    except Exception as e:
        _log(f"Commit failed: {e}")
        return 1

    vm_uuid = (commit.get("vm_uuid") or "").strip()
    committed_app_id = (commit.get("app_id") or app_id).strip()
    status = (commit.get("status") or "").strip().lower() or "creating"

    _log(f"Commit OK: vm_uuid={vm_uuid!r} app_id={committed_app_id!r} status={status!r}")

    # Match MDMA: poll GET /cvms until we have status, then start if stopped/created.
    norm_id = committed_app_id if committed_app_id.startswith("app_") else f"app_{committed_app_id}"
    for attempt in range(18):  # 18 * 10s = 3 min
        if status not in ("creating", ""):
            break
        try:
            cvm = _request("GET", f"/cvms/{norm_id}", api_key, timeout=15) or {}
            status = (cvm.get("status") or cvm.get("hosted", {}).get("status") or "").strip().lower()
            _log(f"Poll {attempt + 1}: status={status or 'unknown'}")
        except RuntimeError as e:
            if "404" in str(e):
                pass
            _log(f"Poll {attempt + 1}: {e}")
        except Exception as e:
            _log(f"Poll {attempt + 1}: {e}")
        if attempt < 17:
            time.sleep(10)

    # Match MDMA: Phala provision creates but may not auto-start; call start if stopped.
    if status in ("stopped", "created") and committed_app_id:
        try:
            _request("POST", f"/cvms/{norm_id}/start", api_key, {}, timeout=30)
            _log(f"Started CVM (status was {status})")
        except RuntimeError as e:
            text = str(e).lower()
            if "404" in text or "not found" in text:
                pass
            elif "already" in text and "running" in text:
                pass
            else:
                _log(f"Start failed (non-fatal): {e}")
        except Exception as e:
            _log(f"Start failed (non-fatal): {e}")

    result = {"app_id": committed_app_id, "vm_uuid": vm_uuid, "status": status}
    _log(f"Done: app_id={committed_app_id} vm_uuid={vm_uuid} status={status}")
    out = json.dumps(result, indent=2) + "\n"

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
    else:
        print(out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
