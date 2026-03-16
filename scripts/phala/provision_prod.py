#!/usr/bin/env python3
"""Provision CVM via Phala REST API with prefer_dev=False (dstack-0.5.7 prod).

Matches MDMA's phala_provider.provision_kms_deployment behavior so probe
lands on the same cluster as production (dstack-0.5.7, not dstack-dev-0.5.7).

Pinned via DSTACK_PREFER_DEV (default false) and DSTACK_VERSION (default 0.5.7).

Usage:
  scripts/phala/provision_prod.py --name NAME --compose COMPOSE_FILE \\
    --instance-type tdx.small [--region REGION] [--output OUTPUT_JSON]

Requires: PHALA_CLOUD_API_KEY
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

# Pinned dstack cluster version (prefer_dev=False => dstack-0.5.7 prod).
DSTACK_VERSION_DEFAULT = "0.5.7"
DSTACK_PREFER_DEV_DEFAULT = False


def main() -> int:
    parser = argparse.ArgumentParser(description="Provision CVM via Phala API (prefer_dev=False)")
    parser.add_argument("--name", required=True, help="CVM name")
    parser.add_argument("--compose", required=True, help="Path to docker-compose file")
    parser.add_argument("--instance-type", default="tdx.small", help="Instance type")
    parser.add_argument("--region", default="", help="Optional region")
    parser.add_argument("--output", default="", help="Output JSON path (default: stdout)")
    args = parser.parse_args()

    api_key = (os.environ.get("PHALA_CLOUD_API_KEY") or "").strip()
    if not api_key:
        print("PHALA_CLOUD_API_KEY is required", file=sys.stderr)
        return 1

    prefer_dev = os.environ.get("DSTACK_PREFER_DEV", str(DSTACK_PREFER_DEV_DEFAULT)).strip().lower() in ("1", "true", "yes")
    dstack_version = (os.environ.get("DSTACK_VERSION") or DSTACK_VERSION_DEFAULT).strip()
    print(f"[provision_prod] Pinned dstack: version={dstack_version} prefer_dev={prefer_dev}", file=sys.stderr)

    base_url = (
        os.environ.get("PHALA_CLOUD_API_PREFIX")
        or "https://cloud-api.phala.com/api/v1"
    ).rstrip("/")

    compose_path = args.compose
    if not os.path.isfile(compose_path):
        print(f"Compose file not found: {compose_path}", file=sys.stderr)
        return 1

    compose_yaml = open(compose_path, encoding="utf-8").read()

    provision_payload = {
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
        print("[provision_prod] POST /cvms/provision ...", file=sys.stderr)
        req = urllib.request.Request(
            f"{base_url}/cvms/provision",
            data=json.dumps(provision_payload).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-API-Key": api_key,
                "X-Phala-Version": "2026-01-21",
            },
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            provision = json.loads(resp.read().decode("utf-8"))
        print(f"[provision_prod] Provision OK: app_id={provision.get('app_id')!r}", file=sys.stderr)
    except Exception as e:
        print(f"[provision_prod] Provision failed: {e}", file=sys.stderr)
        return 1

    app_id = (provision.get("app_id") or "").strip()
    compose_hash = (provision.get("compose_hash") or "").strip()
    if not app_id or not compose_hash:
        print(f"Provision response missing app_id/compose_hash: {provision}", file=sys.stderr)
        return 1

    commit_payload = {"app_id": app_id, "compose_hash": compose_hash}
    try:
        print("[provision_prod] POST /cvms (commit) ...", file=sys.stderr)
        req = urllib.request.Request(
            f"{base_url}/cvms",
            data=json.dumps(commit_payload).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-API-Key": api_key,
                "X-Phala-Version": "2026-01-21",
            },
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            commit = json.loads(resp.read().decode("utf-8"))
        print(f"[provision_prod] Commit OK: vm_uuid={commit.get('vm_uuid')!r} app_id={commit.get('app_id')!r} status={commit.get('status')!r}", file=sys.stderr)
    except Exception as e:
        print(f"[provision_prod] Commit failed: {e}", file=sys.stderr)
        return 1

    vm_uuid = (commit.get("vm_uuid") or "").strip()
    committed_app_id = (commit.get("app_id") or app_id).strip()
    status = (commit.get("status") or "").strip().lower() or "creating"

    # Match MDMA: poll GET /cvms until we have status, then start if stopped/created.
    # Commit may return "creating" before CVM is queryable; MDMA polls get_kms_status.
    norm_id = committed_app_id if committed_app_id.startswith("app_") else f"app_{committed_app_id}"
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": api_key,
        "X-Phala-Version": "2026-01-21",
    }
    for attempt in range(18):  # 18 * 10s = 3 min
        if status not in ("creating", ""):
            break
        try:
            req = urllib.request.Request(f"{base_url}/cvms/{norm_id}", method="GET", headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                cvm = json.loads(resp.read().decode("utf-8"))
            status = (cvm.get("status") or cvm.get("hosted", {}).get("status") or "").strip().lower()
            print(f"[provision_prod] Poll {attempt + 1}: status={status or 'unknown'}", file=sys.stderr)
        except (urllib.error.HTTPError, OSError) as e:
            if isinstance(e, urllib.error.HTTPError) and e.code == 404:
                pass
            print(f"[provision_prod] Poll {attempt + 1}: {e}", file=sys.stderr)
        if attempt < 17:
            time.sleep(10)

    # Match MDMA: Phala provision creates but may not auto-start; call start if stopped.
    if status in ("stopped", "created") and committed_app_id:
        try:
            req = urllib.request.Request(
                f"{base_url}/cvms/{norm_id}/start",
                data=b"",
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": api_key,
                    "X-Phala-Version": "2026-01-21",
                },
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                pass  # 204 or 200
            print(f"[provision_prod] Started CVM (status was {status})", file=sys.stderr)
        except urllib.error.HTTPError as e:
            if e.code in (404,) or "not found" in str(e).lower():
                pass
            elif "already" in str(e).lower() and "running" in str(e).lower():
                pass
            else:
                print(f"[provision_prod] Start failed (non-fatal): {e}", file=sys.stderr)
        except Exception as e:
            print(f"[provision_prod] Start failed (non-fatal): {e}", file=sys.stderr)

    result = {"app_id": committed_app_id, "vm_uuid": vm_uuid, "status": status}
    print(f"[provision_prod] Done: app_id={committed_app_id} vm_uuid={vm_uuid} status={status}", file=sys.stderr)
    out = json.dumps(result, indent=2) + "\n"

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
    else:
        print(out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
