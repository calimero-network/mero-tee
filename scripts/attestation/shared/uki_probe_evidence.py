#!/usr/bin/env python3
"""Evidence from the UKI TDX probe image, and what it shows.

The probe image (mero-tee/mkosi-probe) prints its TD's CCEL event log and a TDX
quote on the serial console as `MEROEV <label> <base64>` lines, each followed by
`MEROEV <label>-sha256 <hex>`. The serial console mixes in the kernel's and
systemd's own lines, so the checksum is what says a payload arrived whole.

  uki_probe_evidence.py extract SERIAL_LOG OUT_DIR
      Write ccel.bin, quote.bin and evidence.json (`quoteB64` + `eventLogB64`,
      the shape tdx_event_log.py reads) from the console output.
  uki_probe_evidence.py report EVIDENCE_JSON --efi EFI [--efi EFI ...]
      Replay the log against the quote's RTMRs, and look for each EFI binary's
      Authenticode SHA-384 among the boot-application events. Prints Markdown;
      exits 1 unless the replay matches and every EFI binary was found.

A match on both is what computing an image's RTMR1 from its build output needs:
the firmware measured exactly the binary the build produced, by a hash anyone
can recompute from that binary.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import struct
import sys

from tdx_event_log import EVENT_TYPES, MR_NAMES, parse, quote_rtmrs, replay

BOOT_APPLICATION = 0x80000003
LINE = re.compile(r"MEROEV (?P<label>[a-z0-9-]+) (?P<value>\S+)")


def authenticode_sha384(pe):
    """The PE/COFF Authenticode image hash: the file without its checksum, its
    certificate-table directory entry and the certificate table itself."""
    (pe_offset,) = struct.unpack_from("<I", pe, 0x3C)
    if pe[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError("not a PE image")
    coff = pe_offset + 4
    (sections,) = struct.unpack_from("<H", pe, coff + 2)
    (optional_size,) = struct.unpack_from("<H", pe, coff + 16)
    optional = coff + 20
    (magic,) = struct.unpack_from("<H", pe, optional)
    if magic not in (0x10B, 0x20B):
        raise ValueError(f"unknown optional header magic {magic:#x}")
    checksum = optional + 64
    directories = optional + (96 if magic == 0x10B else 112)
    certificate_entry = directories + 8 * 4
    (headers_size,) = struct.unpack_from("<I", pe, optional + 60)
    certificate_offset, certificate_size = struct.unpack_from("<II", pe, certificate_entry)

    digest = hashlib.sha384()
    digest.update(pe[:checksum])
    digest.update(pe[checksum + 4 : certificate_entry])
    digest.update(pe[certificate_entry + 8 : headers_size])
    hashed = headers_size

    table = optional + optional_size
    raw = []
    for i in range(sections):
        size, pointer = struct.unpack_from("<II", pe, table + 40 * i + 16)
        if size:
            raw.append((pointer, size))
    for pointer, size in sorted(raw):
        digest.update(pe[pointer : pointer + size])
        hashed += size

    # Whatever follows the sections, short of the certificate table.
    trailing = len(pe) - hashed - (certificate_size if certificate_offset else 0)
    if trailing > 0:
        digest.update(pe[hashed : hashed + trailing])
    return digest.digest()


def extract(args):
    payloads, checksums = {}, {}
    with open(args.serial_log, errors="replace") as f:
        for match in LINE.finditer(f.read()):
            label, value = match["label"], match["value"]
            if label.endswith("-sha256"):
                checksums[label[: -len("-sha256")]] = value
            elif label in ("ccel", "quote"):
                payloads.setdefault(label, []).append(value)
            elif label == "error":
                print(f"the probe reported an error: {value}", file=sys.stderr)
    os.makedirs(args.out_dir, exist_ok=True)
    evidence = {}
    for label, field in (("ccel", "eventLogB64"), ("quote", "quoteB64")):
        if label not in payloads or label not in checksums:
            sys.exit(f"no complete {label} on the serial console")
        data = base64.b64decode("".join(payloads[label]))
        if hashlib.sha256(data).hexdigest() != checksums[label]:
            sys.exit(f"the {label} on the serial console does not match its checksum (interleaved output?)")
        with open(os.path.join(args.out_dir, f"{label}.bin"), "wb") as f:
            f.write(data)
        evidence[field] = base64.b64encode(data).decode()
    with open(os.path.join(args.out_dir, "evidence.json"), "w") as f:
        json.dump(evidence, f)
    print(f"wrote ccel.bin, quote.bin and evidence.json to {args.out_dir}")
    return 0


def report(args):
    with open(args.evidence) as f:
        events = list(parse(base64.b64decode(json.load(f)["eventLogB64"])))
    replayed = replay(events)
    quoted = quote_rtmrs(args.evidence)
    ok = True

    print("## Replay of the event log against the quote\n")
    print("| Register | Quote | Replayed | |")
    print("| --- | --- | --- | --- |")
    for name in quoted:
        same = quoted[name] == replayed[name]
        ok &= same
        print(f"| {name} | `{quoted[name][:24]}…` | `{replayed[name][:24]}…` | {'matches' if same else '**differs**'} |")

    applications = [e for e in events if e["type"] == BOOT_APPLICATION]
    print("\n## EFI binaries the firmware measured\n")
    for path in args.efi:
        with open(path, "rb") as f:
            digest = authenticode_sha384(f.read())
        found = [e for e in applications if e["digest"] == digest]
        ok &= bool(found)
        where = ", ".join(f"event #{e['index']} in {MR_NAMES.get(e['mr'], e['mr'])}" for e in found)
        print(f"- `{os.path.basename(path)}` Authenticode SHA-384 `{digest.hex()[:24]}…`: "
              + (f"measured as {where}" if found else "**not among the measured boot applications**"))

    print("\n## Every event\n")
    print("| # | Register | Type | SHA-384 |")
    print("| --- | --- | --- | --- |")
    for e in events:
        print(f"| {e['index']} | {MR_NAMES.get(e['mr'], e['mr'])} | {EVENT_TYPES.get(e['type'], hex(e['type']))} | `{e['digest'].hex()[:24]}…` |")
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    extract_parser = sub.add_parser("extract")
    extract_parser.add_argument("serial_log")
    extract_parser.add_argument("out_dir")
    report_parser = sub.add_parser("report")
    report_parser.add_argument("evidence")
    report_parser.add_argument("--efi", action="append", required=True)
    args = parser.parse_args()
    return extract(args) if args.command == "extract" else report(args)


if __name__ == "__main__":
    sys.exit(main())
