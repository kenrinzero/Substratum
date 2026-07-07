#!/usr/bin/env python3
"""Author the TOYFS harness fixture (seed tool; DESIGN.md § 3 red-team).

TOYFS v1 (a synthetic container for exercising the gate — NOT a real
format): header = magic b"TOYF" + u32le entry count; entry table = count x
(16-byte NUL-padded name + u32le offset + u32le size); then payload. One
trailing pad byte follows the payload so the off-by-one mutant stays
in-bounds (self-consistent and walkable — the point of red-team (b)).

Writes fixtures/toy/{toy.bin, expected.manifest.json, reference/<files>}.
The expected manifest is built from the GENERATOR's own layout table —
independent of any normalizer — so it is authored truth, not parsed truth.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from substratum.contract import FileEntry, FileSource, FileTree, canonical_manifest, sha256_of

FILES = [
    ("README.TXT", "こんにちは、TOYFS。\n".encode("utf-8")),
    ("DATA/A.BIN", bytes(range(256))),
    ("DATA/B.BIN", b"\x00\x01\x02\x03" * 64),
]


def main() -> None:
    out = Path(__file__).resolve().parent.parent / "fixtures" / "toy"
    (out / "reference").mkdir(parents=True, exist_ok=True)

    header_size = 8 + len(FILES) * 24
    blobs, offset = [], header_size
    for name, data in FILES:
        blobs.append((name, offset, len(data)))
        offset += len(data)

    image = bytearray()
    image += b"TOYF" + struct.pack("<I", len(FILES))
    for (name, off, size) in blobs:
        image += name.encode("ascii").ljust(16, b"\x00") + struct.pack("<II", off, size)
    for _, data in FILES:
        image += data
    image += b"\x00"  # mutant head-room (see module docstring)

    bin_path = out / "toy.bin"
    bin_path.write_bytes(bytes(image))

    for (name, data) in FILES:
        ref = out / "reference" / name
        ref.parent.mkdir(parents=True, exist_ok=True)
        ref.write_bytes(data)

    entries = tuple(
        FileEntry(path=name, kind="file", offset=off, size=size)
        for (name, off, size) in blobs
    )
    tree = FileTree(source=FileSource(bin_path), format="toyfs", entries=entries)
    manifest = canonical_manifest(
        tree, "toy.bin", sha256_of(bin_path), {"generator": "make_toy_fixture v1"}
    )
    (out / "expected.manifest.json").write_bytes(manifest)
    print(f"wrote {bin_path} ({len(image)} bytes) + {len(FILES)} reference files + manifest")


if __name__ == "__main__":
    main()
