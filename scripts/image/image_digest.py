#!/usr/bin/env python3
"""Digest an image's root and initrd per directory, to find what differs
between two builds that should be identical.

Two builds of one commit should give one root, and so one RTMR1-3. When they
do not, run this on both and diff the output: every directory whose content
differs shows up with a different digest, down to the one that holds the
differing file.

  image_digest.py root DIR        a root tree (fsck.erofs --extract of the root partition)
  image_digest.py initrd FILE     a UKI's .initrd: newc cpio archives, each maybe zstd-compressed
  image_digest.py uki FILE        the .initrd section of a UKI

Each line is `<digest12> <entries> <path>`: the digest covers every entry
below the directory (name, type, mode, owner, size, content or link target;
not a directory's own size, which is the extracting filesystem's), so a
parent differs whenever any child does. `--files-under DIR` also lists every
entry below DIR, once the differing directory is known.

The initrd needs the zstandard module (pip install zstandard).
"""

import argparse
import hashlib
import os
import stat
import sys
from collections import defaultdict
from pathlib import Path


def entry_line(name, mode, uid, gid, size, payload):
    return f"{name}\0{mode:o}\0{uid}\0{gid}\0{size}\0{hashlib.sha256(payload).hexdigest()}\n"


def walk_root(root):
    """(relative path, entry line) for every entry below root."""
    root = Path(root)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            path = Path(dirpath) / name
            st = path.lstat()
            size = st.st_size
            if stat.S_ISLNK(st.st_mode):
                payload = os.readlink(path).encode()
            elif stat.S_ISREG(st.st_mode):
                payload = path.read_bytes()
            else:
                payload, size = b"", 0
            rel = "/" + str(path.relative_to(root))
            yield rel, entry_line(name, st.st_mode, st.st_uid, st.st_gid, size, payload)


def decompress(data):
    """The initrd as plain cpio: each zstd frame decompressed in place, the
    uncompressed archives between them kept."""
    import zstandard
    magic = b"\x28\xb5\x2f\xfd"
    out, pos = bytearray(), 0
    while pos < len(data):
        if data[pos:pos + 4] == magic:
            obj = zstandard.ZstdDecompressor().decompressobj()
            out += obj.decompress(data[pos:])
            pos = len(data) - len(obj.unused_data)
        else:
            nxt = data.find(magic, pos)
            nxt = len(data) if nxt < 0 else nxt
            out += data[pos:nxt]
            pos = nxt
    return bytes(out)


def walk_cpio(data):
    """(path, entry line) for every entry of concatenated newc archives. A
    path in more than one archive is listed once per archive, in order."""
    pos, n = 0, 0
    while pos + 110 <= len(data):
        if data[pos:pos + 6] not in (b"070701", b"070702"):
            pos += 1  # padding between archives
            continue
        fields = [int(data[pos + 6 + 8 * i:pos + 14 + 8 * i], 16) for i in range(13)]
        mode, uid, gid, filesize, namesize = fields[1], fields[2], fields[3], fields[6], fields[11]
        name_start = pos + 110
        name = data[name_start:name_start + namesize - 1].decode(errors="replace")
        body = (name_start + namesize + 3) & ~3
        payload = data[body:body + filesize]
        pos = (body + filesize + 3) & ~3
        if name == "TRAILER!!!":
            n += 1
            continue
        name = name.lstrip("./")
        if not name:
            continue
        yield "/" + name, entry_line(name.rsplit("/", 1)[-1] + f"#{n}", mode, uid, gid, filesize, payload)


def digest(entries):
    """Per-directory digests over everything below each directory."""
    hashes, counts = defaultdict(hashlib.sha256), defaultdict(int)
    for path, line in entries:
        # The entry counts towards every ancestor.
        parts = path.split("/")[1:-1]
        for depth in range(len(parts) + 1):
            ancestor = "/" + "/".join(parts[:depth])
            hashes[ancestor].update(line.encode())
            counts[ancestor] += 1
    return hashes, counts


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("kind", choices=["root", "initrd", "uki"])
    parser.add_argument("path")
    parser.add_argument("--files-under", action="append", default=[], metavar="DIR",
                        help="also list every entry below DIR")
    args = parser.parse_args()
    if args.kind == "root":
        entries = list(walk_root(args.path))
    else:
        data = Path(args.path).read_bytes()
        if args.kind == "uki":
            sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "attestation" / "shared"))
            from compute_rtmr import pe_sections
            data = pe_sections(data)[".initrd"]
        entries = list(walk_cpio(decompress(data)))
    hashes, counts = digest(entries)
    for directory in sorted(hashes):
        print(f"{hashes[directory].hexdigest()[:12]} {counts[directory]:6d} {directory}")
    for prefix in args.files_under:
        print(f"## {prefix}")
        for path, line in entries:
            if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
                print(f"{hashlib.sha256(line.encode()).hexdigest()[:12]} {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
