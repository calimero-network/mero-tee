#!/usr/bin/env bash
# scripts/attestation/shared/tdx_event_log.py reads a TD's CCEL event log so a
# failed KMS join can say WHICH measured event differs between two replicas.
# Build two synthetic crypto-agile logs that differ in one RTMR0 UEFI boot
# variable, and check the parser lists the events, the replay reproduces the
# RTMRs a quote carries, and the diff names exactly that variable.
#
# Usage: scripts/ci/tests/tdx-event-log-test.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TOOL="${REPO_ROOT}/scripts/attestation/shared/tdx_event_log.py"
work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

python3 - "${work}" <<'PY'
import base64, hashlib, json, struct, sys

work = sys.argv[1]

def header():
    spec = b"Spec ID Event03\x00" + struct.pack("<IBBBBI", 0, 0, 2, 0, 2, 1) + struct.pack("<HH", 0x000C, 48) + b"\x00"
    return struct.pack("<II", 0, 3) + bytes(20) + struct.pack("<I", len(spec)) + spec

def event(mr, kind, data):
    digest = hashlib.sha384(data).digest()
    return struct.pack("<III", mr, kind, 1) + struct.pack("<H", 0x000C) + digest + struct.pack("<I", len(data)) + data, digest

def variable(name, value):
    encoded = name.encode("utf-16-le")
    return bytes(16) + struct.pack("<QQ", len(name), len(value)) + encoded + value

def build(boot_order):
    events = [
        (1, 0x80000001, variable("SecureBoot", b"\x01")),
        (1, 0x80000002, variable("BootOrder", boot_order)),
        (1, 0x00000004, b"\x00\x00\x00\x00"),
        (2, 0x80000003, b"shimx64.efi"),
        (3, 0x0000000D, b"root=/dev/mapper/root roothash=00"),
    ]
    raw = header()
    registers = [bytes(48)] * 4
    for mr, kind, data in events:
        record, digest = event(mr, kind, data)
        raw += record
        registers[mr - 1] = hashlib.sha384(registers[mr - 1] + digest).digest()
    raw += b"\xff" * 64
    quote = bytearray(48 + 584)
    for i, value in enumerate(registers):
        offset = 48 + 328 + 48 * i
        quote[offset : offset + 48] = value
    return raw, bytes(quote)

for label, order in (("a", b"\x02\x00"), ("b", b"\x02\x00\x01\x00")):
    raw, quote = build(order)
    with open(f"{work}/{label}.ccel", "wb") as f:
        f.write(raw)
    with open(f"{work}/{label}-attest.json", "w") as f:
        json.dump({"quoteB64": base64.b64encode(quote).decode(), "eventLogB64": base64.b64encode(raw).decode()}, f)
PY

fail() { echo "FAIL: $*"; exit 1; }

shown="$(python3 "${TOOL}" show "${work}/a.ccel" --attest-response "${work}/a-attest.json")" \
  || fail "the replay of a log does not match its own quote: ${shown}"
grep -q 'RTMR0 EV_EFI_VARIABLE_BOOT .*variable BootOrder' <<< "${shown}" || fail "BootOrder is not listed: ${shown}"
grep -q 'replayed RTMR0 .* matches the quote' <<< "${shown}" || fail "RTMR0 replay not reported: ${shown}"

if python3 "${TOOL}" show "${work}/a-attest.json" --attest-response "${work}/b-attest.json" >/dev/null; then
  fail "a log replayed against another TD's quote passed"
fi

diffed="$(python3 "${TOOL}" diff "${work}/a-attest.json" "${work}/b-attest.json" --imr 0 || true)"
grep -q 'A: .*variable BootOrder (2 bytes) 0200' <<< "${diffed}" || fail "diff does not name A's BootOrder: ${diffed}"
grep -q 'B: .*variable BootOrder (4 bytes) 02000100' <<< "${diffed}" || fail "diff does not name B's BootOrder: ${diffed}"
[[ "$(grep -c '^--- event' <<< "${diffed}")" == "1" ]] || fail "diff reports more than the one event: ${diffed}"

python3 "${TOOL}" diff "${work}/a.ccel" "${work}/a-attest.json" --imr 0 | grep -q 'the two logs record the same events' \
  || fail "identical logs reported as different"

echo "PASS: tdx-event-log"
