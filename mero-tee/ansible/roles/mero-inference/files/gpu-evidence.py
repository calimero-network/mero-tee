#!/usr/bin/env python3
"""Print NVIDIA confidential-computing evidence for a nonce, in the shape
NVIDIA's NRAS takes (POST /v3/attest/gpu):

  {"nonce": "<hex>", "arch": "HOPPER", "evidence_list": [{"certificate": "<b64>", "evidence": "<b64>"}]}

`evidence` is each GPU's attestation report over the nonce, `certificate` its
attestation certificate chain (PEM), both read from the driver through NVML.
mero-inference-gate runs it for every /attest; inference-init runs it once
with `--check` to have NRAS accept this TD's GPUs before setting them ready.

  gpu-evidence.py <nonce hex>
  gpu-evidence.py --check            (random nonce, NRAS, exit 1 unless it passes)
"""

import base64
import json
import os
import sys
import urllib.request

NRAS = "https://nras.attestation.nvidia.com/v3/attest/gpu"
ARCHES = {9: "HOPPER", 10: "BLACKWELL"}


def collect(nonce_hex):
    import pynvml

    nonce = bytes.fromhex(nonce_hex)
    if len(nonce) != 32:
        raise SystemExit("gpu-evidence: the nonce is not 32 bytes")
    pynvml.nvmlInit()
    try:
        evidence, arches = [], set()
        for index in range(pynvml.nvmlDeviceGetCount()):
            handle = pynvml.nvmlDeviceGetHandleByIndex(index)
            arch = pynvml.nvmlDeviceGetArchitecture(handle)
            if arch not in ARCHES:
                raise SystemExit(f"gpu-evidence: GPU {index} has architecture {arch}, which NRAS does not attest")
            arches.add(ARCHES[arch])
            report = pynvml.nvmlDeviceGetConfComputeGpuAttestationReport(handle, nonce)
            certificate = pynvml.nvmlDeviceGetConfComputeGpuCertificate(handle)
            evidence.append({
                "certificate": base64.b64encode(
                    bytes(certificate.attestationCertChain[: certificate.attestationCertChainSize])
                ).decode(),
                "evidence": base64.b64encode(
                    bytes(report.attestationReport[: report.attestationReportSize])
                ).decode(),
            })
        if not evidence:
            raise SystemExit("gpu-evidence: no GPU")
        if len(arches) != 1:
            raise SystemExit(f"gpu-evidence: mixed GPU architectures {sorted(arches)}")
        return {"nonce": nonce_hex, "arch": arches.pop(), "evidence_list": evidence}
    finally:
        pynvml.nvmlShutdown()


def check():
    """NRAS's verdict on this TD's GPUs, for a fresh nonce. Its answer comes
    over TLS from NVIDIA; clients verify its signature themselves."""
    payload = collect(os.urandom(32).hex())
    request = urllib.request.Request(
        NRAS, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        body = json.load(response)
    token = body[0][1] if isinstance(body, list) and body and isinstance(body[0], list) else None
    if not isinstance(token, str) or token.count(".") != 2:
        raise SystemExit(f"gpu-evidence: NRAS answered no token: {str(body)[:300]}")
    claims_b64 = token.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(claims_b64 + "=" * (-len(claims_b64) % 4)))
    if claims.get("x-nvidia-overall-att-result") is not True:
        raise SystemExit(f"gpu-evidence: NRAS did not accept the GPUs: {json.dumps(claims)[:500]}")
    print(f"NRAS accepted {len(payload['evidence_list'])} {payload['arch']} GPU(s)")


def main():
    if sys.argv[1:] == ["--check"]:
        check()
    elif len(sys.argv) == 2:
        print(json.dumps(collect(sys.argv[1].strip().lower()), separators=(",", ":")))
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
