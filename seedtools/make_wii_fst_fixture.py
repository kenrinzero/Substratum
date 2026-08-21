#!/usr/bin/env python3
"""Author a synthetic decrypted Wii DATA partition with a known FST.

The runtime ``wii-fst`` normalizer walks the FST of a decrypted DATA
partition. This seedtool authors a small committed synthetic partition that
exercises the FST walker — including nested directories — without any retail
bytes or retail key. It is a *decrypted* image (the wii-partition decode is
already proven independently; this fixture starts from its output shape).

Layout authored (all word-offset convention per the Wii format):
  - boot.bin header (0x440 bytes): FST offset/size at 0x424/0x428 (word-shifted).
  - file payloads at known offsets.
  - FST node table + string table.

The expected manifest is authored HERE from the known structure (not by
running the normalizer under test), so the gate's check 2 compares the
normalizer's output against an independently-derived truth.

Usage:
    uv run python seedtools/make_wii_fst_fixture.py
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from substratum.contract import (  # noqa: E402
    FileEntry,
    FileSource,
    FileTree,
    canonical_manifest,
    sha256_of,
)

OUTPUT = ROOT / "fixtures" / "wii_fst" / "synthetic"
STAGER = "make_wii_fst_fixture v1"

_HEADER_SIZE = 0x440
_NODE_SIZE = 0x0C
_WORD_SHIFT = 2
_FST_OFF_FIELD = 0x424
_FST_SIZE_FIELD = 0x428


def _build_fst(entries: list[dict]) -> bytes:
    """Build an FST byte blob (node table + string table) from a node spec.

    Each node: dict with type ('file'|'dir'), name, and for files
    offset (word)/size, for dirs parent/next. Root is implicit (node 0).
    Returns the FST bytes; the caller records its size.
    """
    nodes = bytearray()
    strtab = bytearray(b"\x00")  # root name is offset 0 = empty string

    # Root node: type=dir, name_off=0, parent=0, next=len(entries)+1
    total_nodes = len(entries) + 1  # +1 for root
    nodes.append(1)  # type = 1 (dir)
    nodes += b"\x00\x00\x00"  # name offset 0 (3 bytes)
    nodes += struct.pack(">I", 0)  # parent = 0
    nodes += struct.pack(">I", total_nodes)  # next = node count

    name_offsets: dict[str, int] = {}

    def _name_off(name: str) -> int:
        if name not in name_offsets:
            name_offsets[name] = len(strtab)
            strtab.extend(name.encode("ascii"))
            strtab.append(0)  # null terminator
        return name_offsets[name]

    for entry in entries:
        noff = _name_off(entry["name"])
        if entry["type"] == "file":
            nodes.append(0)  # type 0 = file
            nodes += struct.pack(">I", noff)[1:]  # name offset (3 bytes)
            nodes += struct.pack(">I", entry["offset"] >> _WORD_SHIFT)  # word offset
            nodes += struct.pack(">I", entry["size"])
        else:  # dir
            nodes.append(1)  # type 1 = dir
            nodes += struct.pack(">I", noff)[1:]
            nodes += struct.pack(">I", entry["parent"])
            nodes += struct.pack(">I", entry["next"])
    return bytes(nodes) + bytes(strtab)


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)

    # Author a small filesystem with nesting:
    #   files/a.bin      (16 bytes of 0xAA)
    #   files/b.dat      (32 bytes of 0xBB)
    #   files/sub/c.txt  (8 bytes of 0xCC)
    # File payloads placed after the header; FST after the payloads.
    payload_a = b"\xAA" * 16
    payload_b = b"\xBB" * 32
    payload_c = b"\xCC" * 8
    off_a = _HEADER_SIZE
    off_b = off_a + len(payload_a)
    off_c = off_b + len(payload_b)
    fst_byte_off = off_c + len(payload_c)

    # Node indices: 0=root, 1=files(dir), 2=files/a.bin, 3=files/b.dat,
    # 4=files/sub(dir), 5=files/sub/c.txt
    nodes = [
        {"type": "dir", "name": "files", "parent": 0, "next": 6},
        {"type": "file", "name": "a.bin", "offset": off_a, "size": len(payload_a)},
        {"type": "file", "name": "b.dat", "offset": off_b, "size": len(payload_b)},
        {"type": "dir", "name": "sub", "parent": 1, "next": 6},
        {"type": "file", "name": "c.txt", "offset": off_c, "size": len(payload_c)},
    ]
    fst = _build_fst(nodes)
    # The Wii FST size field is word-shifted (÷4 on write, ×4 on read), so the
    # stored FST must be padded to a 4-byte boundary to round-trip exactly.
    while len(fst) % 4 != 0:
        fst += b"\x00"
    total_size = fst_byte_off + len(fst)

    image = bytearray(total_size)
    # boot.bin: a printable disc-ID so the sniffer accepts it.
    image[0:6] = b"SYNTH1"
    # FST offset/size in the header (word-shifted).
    struct.pack_into(">I", image, _FST_OFF_FIELD, fst_byte_off >> _WORD_SHIFT)
    struct.pack_into(">I", image, _FST_SIZE_FIELD, len(fst) >> _WORD_SHIFT)
    # File payloads.
    image[off_a : off_a + len(payload_a)] = payload_a
    image[off_b : off_b + len(payload_b)] = payload_b
    image[off_c : off_c + len(payload_c)] = payload_c
    # FST.
    image[fst_byte_off : fst_byte_off + len(fst)] = fst

    partition_path = OUTPUT / "partition.bin"
    partition_path.write_bytes(bytes(image))

    # Independently-authored expected manifest (NOT from the normalizer).
    entries = [
        FileEntry("files", "dir", 0, 0),
        FileEntry("files/a.bin", "file", off_a, len(payload_a)),
        FileEntry("files/b.dat", "file", off_b, len(payload_b)),
        FileEntry("files/sub", "dir", 0, 0),
        FileEntry("files/sub/c.txt", "file", off_c, len(payload_c)),
    ]
    tree = FileTree(
        source=FileSource(partition_path), format="wii-fst", entries=tuple(entries)
    )
    manifest = canonical_manifest(
        tree, partition_path.name, sha256_of(partition_path), {"generator": STAGER}
    )
    (OUTPUT / "expected.manifest.json").write_bytes(manifest)

    # Expected payload descriptors for the fidelity check (reference bytes are
    # the committed payloads themselves — derived from the known structure,
    # not from the normalizer under test).
    # write_bytes, not write_text: write_text maps \n to the platform newline,
    # so on this Windows host it silently emitted a CRLF descriptor.
    (OUTPUT / "payloads.json").write_bytes(
        (
            json.dumps(
                {
                    "files/a.bin": {
                        "offset": off_a,
                        "fill": "AA",
                        "size": len(payload_a),
                    },
                    "files/b.dat": {
                        "offset": off_b,
                        "fill": "BB",
                        "size": len(payload_b),
                    },
                    "files/sub/c.txt": {
                        "offset": off_c,
                        "fill": "CC",
                        "size": len(payload_c),
                    },
                },
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    )

    print(
        f"authored synthetic decrypted Wii DATA partition: {total_size} bytes, "
        f"5 FST entries (3 files, 2 dirs, nested)\n"
        f"  partition -> {partition_path}\n"
        f"  manifest  -> {OUTPUT / 'expected.manifest.json'}\n"
        f"  payloads  -> {OUTPUT / 'payloads.json'}"
    )


if __name__ == "__main__":
    main()
