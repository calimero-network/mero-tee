#!/usr/bin/env python3
"""Replay and compare TDX event logs (the ACPI CCEL table).

A TD's firmware and boot chain record every measurement they extend into
RTMR0-3 in the CCEL event log (TCG crypto-agile format, SHA-384 digests). Two
TDs whose quotes carry different RTMRs differ in at least one of these events.

  tdx_event_log.py show LOG [--attest-response ATTEST.json]
      List the events. With --attest-response, also replay the log and check
      the RTMRs it yields against the quote's.
  tdx_event_log.py diff LOG_A LOG_B [--imr N]
      Print the events of RTMR N (default all) where the two logs differ.

LOG is either the raw CCEL bytes or a mero-kms /attest response JSON carrying
`eventLogB64`.
"""

import argparse
import base64
import hashlib
import json
import struct
import sys

SHA384_ALG = 0x000C
NO_ACTION = 0x00000003

# The CCEL "PCR index" is an MR index: 0 is MRTD, 1-4 are RTMR0-3.
MR_NAMES = {0: "MRTD", 1: "RTMR0", 2: "RTMR1", 3: "RTMR2", 4: "RTMR3"}

EVENT_TYPES = {
    0x00000001: "EV_POST_CODE",
    0x00000003: "EV_NO_ACTION",
    0x00000004: "EV_SEPARATOR",
    0x00000005: "EV_ACTION",
    0x00000006: "EV_EVENT_TAG",
    0x00000007: "EV_S_CRTM_CONTENTS",
    0x00000008: "EV_S_CRTM_VERSION",
    0x0000000D: "EV_IPL",
    0x0000000F: "EV_NONHOST_CONFIG",
    0x00000012: "EV_TABLE_OF_DEVICES",
    0x80000001: "EV_EFI_VARIABLE_DRIVER_CONFIG",
    0x80000002: "EV_EFI_VARIABLE_BOOT",
    0x80000003: "EV_EFI_BOOT_SERVICES_APPLICATION",
    0x80000004: "EV_EFI_BOOT_SERVICES_DRIVER",
    0x80000005: "EV_EFI_RUNTIME_SERVICES_DRIVER",
    0x80000006: "EV_EFI_GPT_EVENT",
    0x80000007: "EV_EFI_ACTION",
    0x80000008: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
    0x80000009: "EV_EFI_HANDOFF_TABLES",
    0x8000000A: "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
    0x8000000B: "EV_EFI_HANDOFF_TABLES2",
    0x8000000C: "EV_EFI_VARIABLE_BOOT2",
    0x800000E0: "EV_EFI_VARIABLE_AUTHORITY",
    0x800000E1: "EV_EFI_SPDM_FIRMWARE_BLOB",
    0x800000E2: "EV_EFI_SPDM_FIRMWARE_CONFIG",
}

VARIABLE_EVENTS = {0x80000001, 0x80000002, 0x8000000C, 0x800000E0}


def load_log(path):
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:1] in (b"{", b"["):
        response = json.loads(raw)
        encoded = response.get("eventLogB64")
        if not encoded:
            sys.exit(f"{path}: no eventLogB64 in the attest response")
        return base64.b64decode(encoded)
    return raw


def describe(event_type, data):
    """A short, human-readable summary of an event's data."""
    if event_type in VARIABLE_EVENTS and len(data) >= 32:
        name_len, data_len = struct.unpack_from("<QQ", data, 16)
        name = data[32 : 32 + 2 * name_len].decode("utf-16-le", "replace")
        value = data[32 + 2 * name_len : 32 + 2 * name_len + data_len]
        return f"variable {name} ({data_len} bytes) {value.hex()[:96]}"
    printable = data.rstrip(b"\x00")
    if printable and all(32 <= b < 127 for b in printable):
        return printable.decode()
    return f"{len(data)} bytes {data.hex()[:96]}"


def parse(raw):
    """Yield the log's events as dicts. The first event is the SHA-1-format
    spec header; the rest are TCG_PCR_EVENT2 records."""
    offset = 0
    _, _ = struct.unpack_from("<II", raw, offset)
    offset += 8 + 20
    (header_size,) = struct.unpack_from("<I", raw, offset)
    offset += 4
    header = raw[offset : offset + header_size]
    offset += header_size
    digest_sizes = {}
    (algorithms,) = struct.unpack_from("<I", header, 24)
    for i in range(algorithms):
        alg, size = struct.unpack_from("<HH", header, 28 + 4 * i)
        digest_sizes[alg] = size

    index = 0
    while offset + 12 <= len(raw):
        mr, event_type, count = struct.unpack_from("<III", raw, offset)
        # The table is padded past the last event.
        if event_type in (0x00000000, 0xFFFFFFFF):
            break
        offset += 12
        digests = {}
        for _ in range(count):
            (alg,) = struct.unpack_from("<H", raw, offset)
            size = digest_sizes[alg]
            digests[alg] = raw[offset + 2 : offset + 2 + size]
            offset += 2 + size
        (size,) = struct.unpack_from("<I", raw, offset)
        offset += 4
        data = raw[offset : offset + size]
        offset += size
        yield {
            "index": index,
            "mr": mr,
            "type": event_type,
            "digest": digests.get(SHA384_ALG, b""),
            "data": data,
        }
        index += 1


def replay(events):
    registers = {mr: bytes(48) for mr in range(1, 5)}
    for event in events:
        if event["type"] == NO_ACTION or event["mr"] not in registers:
            continue
        registers[event["mr"]] = hashlib.sha384(registers[event["mr"]] + event["digest"]).digest()
    return {MR_NAMES[mr]: value.hex() for mr, value in registers.items()}


def line(event):
    name = EVENT_TYPES.get(event["type"], hex(event["type"]))
    mr = MR_NAMES.get(event["mr"], str(event["mr"]))
    return f"#{event['index']:<3} {mr:<5} {name:<32} {event['digest'].hex()[:24]}  {describe(event['type'], event['data'])}"


def quote_rtmrs(attest_path):
    """RTMR0-3 from the raw TDX v4 quote in a mero-kms /attest response."""
    with open(attest_path) as f:
        quote = base64.b64decode(json.load(f)["quoteB64"])
    body = 48
    rtmr0 = body + 16 + 48 + 48 + 8 + 8 + 8 + 48 * 4
    return {f"RTMR{i}": quote[rtmr0 + 48 * i : rtmr0 + 48 * (i + 1)].hex() for i in range(4)}


def show(args):
    events = list(parse(load_log(args.log)))
    for event in events:
        print(line(event))
    if args.attest_response:
        replayed = replay(events)
        quoted = quote_rtmrs(args.attest_response)
        mismatched = [name for name in quoted if quoted[name] != replayed[name]]
        for name in quoted:
            state = "matches the quote" if name not in mismatched else "DIFFERS from the quote"
            print(f"replayed {name} {replayed[name][:24]}... {state}")
        if mismatched:
            return 1
    return 0


def diff(args):
    wanted = None if args.imr is None else args.imr + 1
    a = [e for e in parse(load_log(args.log_a)) if wanted is None or e["mr"] == wanted]
    b = [e for e in parse(load_log(args.log_b)) if wanted is None or e["mr"] == wanted]
    differing = 0
    for position in range(max(len(a), len(b))):
        left = a[position] if position < len(a) else None
        right = b[position] if position < len(b) else None
        if left and right and left["digest"] == right["digest"] and left["type"] == right["type"]:
            continue
        differing += 1
        print(f"--- event {position} of the selected registers differs")
        print(f"  A: {line(left) if left else '(none)'}")
        print(f"  B: {line(right) if right else '(none)'}")
    if not differing:
        print("the two logs record the same events")
    return 1 if differing else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    show_parser = sub.add_parser("show")
    show_parser.add_argument("log")
    show_parser.add_argument("--attest-response")
    diff_parser = sub.add_parser("diff")
    diff_parser.add_argument("log_a")
    diff_parser.add_argument("log_b")
    diff_parser.add_argument("--imr", type=int, choices=range(4), help="compare only RTMR<imr>")
    args = parser.parse_args()
    return show(args) if args.command == "show" else diff(args)


if __name__ == "__main__":
    sys.exit(main())
