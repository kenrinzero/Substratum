#!/usr/bin/env python3
"""Author the synthetic XDVDFS fixture (NORMALIZERS.md row `xdvdfs`).

The normalizer uses the recommended defaults from the design spec:
- synthetic tier-1 fixture,
- structural self-consistency for the differential,
- stdlib-only authoring.
"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from substratum.contract import FileEntry, FileSource, FileTree, canonical_manifest, sha256_of

GENERATOR = "make_xdvdfs_fixture v1"
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "fixtures" / "xdvdfs" / "synthetic"
REFERENCE = OUT / "reference"

_MAGIC = b"MICROSOFT*XBOX*MEDIA"
_SECTOR = 0x800
_DESC_OFFSET = 0x10000
_DIR_ATTR = 0x10


def _blob(tag: bytes, size: int) -> bytes:
    """Deterministic pseudo-random payload (sha256 chain)."""
    out = bytearray()
    h = tag
    while len(out) < size:
        h = hashlib.sha256(h).digest()
        out += h
    return bytes(out[:size])


FILES = {
    "README.TXT": b"Substratum synthetic XDVDFS fixture. Authored by seedtools/make_xdvdfs_fixture.py.\n",
    "BOOT/APP.BIN": _blob(b"substratum-xdvdfs-app", 4096),
    "DATA/A.BIN": bytes(range(256)),
    "DATA/B.BIN": b"\x00\x01\x02\x03" * 512,
    "DATA/EMPTY.BIN": b"",
    "DATA/SUB/C.DAT": _blob(b"substratum-xdvdfs-c", 2048),
}


class EntrySpec:
    def __init__(self, name: str, is_dir: bool, attrs: int = 0) -> None:
        self.name = name
        self.is_dir = is_dir
        self.attrs = attrs
        self.start_sector = 0
        self.size = 0
        self.l_offset = 0
        self.r_offset = 0


def _serialize_directory_table(entries: list[EntrySpec], table_size: int, entry_offsets: list[int]) -> bytes:
    """Serialize a directory table with explicit LCRS pointers."""
    table = bytearray(b"\x00" * table_size)
    for entry, offset in zip(entries, entry_offsets):
        name_bytes = entry.name.encode("ascii")
        table[offset + 0 : offset + 2] = struct.pack("<H", entry.l_offset)
        table[offset + 2 : offset + 4] = struct.pack("<H", entry.r_offset)
        table[offset + 4 : offset + 8] = struct.pack("<I", entry.start_sector)
        table[offset + 8 : offset + 12] = struct.pack("<I", entry.size)
        table[offset + 0x0C] = entry.attrs
        table[offset + 0x0D] = len(name_bytes)
        table[offset + 0x0E : offset + 0x0E + len(name_bytes)] = name_bytes
    return bytes(table)


def build_image() -> tuple[bytes, list[FileEntry]]:
    directories = {
        "root": [EntrySpec("BOOT", True, _DIR_ATTR), EntrySpec("DATA", True, _DIR_ATTR), EntrySpec("README.TXT", False, 0x20)],
        "BOOT": [EntrySpec("APP.BIN", False, 0x20)],
        "DATA": [EntrySpec("A.BIN", False, 0x20), EntrySpec("B.BIN", False, 0x20), EntrySpec("EMPTY.BIN", False, 0x20), EntrySpec("SUB", True, _DIR_ATTR)],
        "DATA/SUB": [EntrySpec("C.DAT", False, 0x20)],
    }
    entry_offsets = {
        "root": [0x00, 0x20, 0x40],
        "BOOT": [0x00],
        "DATA": [0x00, 0x20, 0x40, 0x60],
        "DATA/SUB": [0x00],
    }

    root_dir_sector = 0x22
    boot_dir_sector = 0x23
    data_dir_sector = 0x24
    sub_dir_sector = 0x25

    payload_sector = 0x26
    payload_offsets: dict[str, tuple[int, int]] = {}
    for path, data in FILES.items():
        payload_offsets[path] = (payload_sector, len(data))
        payload_sector += (len(data) + _SECTOR - 1) // _SECTOR

    for entry in directories["root"]:
        if entry.name == "BOOT":
            entry.start_sector = boot_dir_sector
            entry.size = _SECTOR
        elif entry.name == "DATA":
            entry.start_sector = data_dir_sector
            entry.size = _SECTOR
        else:
            entry.start_sector = payload_offsets["README.TXT"][0]
            entry.size = len(FILES["README.TXT"])

    for entry in directories["BOOT"]:
        entry.start_sector = payload_offsets["BOOT/APP.BIN"][0]
        entry.size = len(FILES["BOOT/APP.BIN"])

    for entry in directories["DATA"]:
        if entry.name == "A.BIN":
            entry.start_sector = payload_offsets["DATA/A.BIN"][0]
            entry.size = len(FILES["DATA/A.BIN"])
        elif entry.name == "B.BIN":
            entry.start_sector = payload_offsets["DATA/B.BIN"][0]
            entry.size = len(FILES["DATA/B.BIN"])
        elif entry.name == "EMPTY.BIN":
            entry.start_sector = payload_offsets["DATA/EMPTY.BIN"][0]
            entry.size = len(FILES["DATA/EMPTY.BIN"])
        else:
            entry.start_sector = sub_dir_sector
            entry.size = _SECTOR

    for entry in directories["DATA/SUB"]:
        entry.start_sector = payload_offsets["DATA/SUB/C.DAT"][0]
        entry.size = len(FILES["DATA/SUB/C.DAT"])

    directories["root"][0].r_offset = 0x20 // 4
    directories["root"][1].l_offset = 0
    directories["root"][1].r_offset = 0x40 // 4
    directories["root"][2].l_offset = 0
    directories["root"][2].r_offset = 0

    directories["BOOT"][0].l_offset = 0
    directories["BOOT"][0].r_offset = 0

    directories["DATA"][0].r_offset = 0x20 // 4
    directories["DATA"][1].r_offset = 0x40 // 4
    directories["DATA"][2].r_offset = 0x60 // 4
    directories["DATA"][3].l_offset = 0
    directories["DATA"][3].r_offset = 0

    directories["DATA/SUB"][0].l_offset = 0
    directories["DATA/SUB"][0].r_offset = 0

    table_bytes = {
        "root": _serialize_directory_table(directories["root"], _SECTOR, entry_offsets["root"]),
        "BOOT": _serialize_directory_table(directories["BOOT"], _SECTOR, entry_offsets["BOOT"]),
        "DATA": _serialize_directory_table(directories["DATA"], _SECTOR, entry_offsets["DATA"]),
        "DATA/SUB": _serialize_directory_table(directories["DATA/SUB"], _SECTOR, entry_offsets["DATA/SUB"]),
    }

    image_size = max(_DESC_OFFSET + _SECTOR + _SECTOR * 4, (payload_sector) * _SECTOR) + 1
    image = bytearray(b"\xFF" * image_size)

    image[_DESC_OFFSET : _DESC_OFFSET + len(_MAGIC)] = _MAGIC
    image[_DESC_OFFSET + 0x7EC : _DESC_OFFSET + 0x7EC + len(_MAGIC)] = _MAGIC
    struct.pack_into("<I", image, _DESC_OFFSET + 0x14, root_dir_sector)
    struct.pack_into("<I", image, _DESC_OFFSET + 0x18, _SECTOR)

    image[root_dir_sector * _SECTOR : root_dir_sector * _SECTOR + _SECTOR] = table_bytes["root"]
    image[boot_dir_sector * _SECTOR : boot_dir_sector * _SECTOR + _SECTOR] = table_bytes["BOOT"]
    image[data_dir_sector * _SECTOR : data_dir_sector * _SECTOR + _SECTOR] = table_bytes["DATA"]
    image[sub_dir_sector * _SECTOR : sub_dir_sector * _SECTOR + _SECTOR] = table_bytes["DATA/SUB"]

    for path, data in FILES.items():
        sector, size = payload_offsets[path]
        start = sector * _SECTOR
        image[start : start + size] = data

    entries = [
        FileEntry("BOOT", "dir", 0, 0),
        FileEntry("BOOT/APP.BIN", "file", payload_offsets["BOOT/APP.BIN"][0] * _SECTOR, len(FILES["BOOT/APP.BIN"])),
        FileEntry("DATA", "dir", 0, 0),
        FileEntry("DATA/A.BIN", "file", payload_offsets["DATA/A.BIN"][0] * _SECTOR, len(FILES["DATA/A.BIN"])),
        FileEntry("DATA/B.BIN", "file", payload_offsets["DATA/B.BIN"][0] * _SECTOR, len(FILES["DATA/B.BIN"])),
        FileEntry("DATA/EMPTY.BIN", "file", payload_offsets["DATA/EMPTY.BIN"][0] * _SECTOR, len(FILES["DATA/EMPTY.BIN"])),
        FileEntry("DATA/SUB", "dir", 0, 0),
        FileEntry("DATA/SUB/C.DAT", "file", payload_offsets["DATA/SUB/C.DAT"][0] * _SECTOR, len(FILES["DATA/SUB/C.DAT"])),
        FileEntry("README.TXT", "file", payload_offsets["README.TXT"][0] * _SECTOR, len(FILES["README.TXT"])),
    ]
    return bytes(image), entries


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    REFERENCE.mkdir(parents=True, exist_ok=True)

    image, entries = build_image()
    image_path = OUT / "game.xiso"
    image_path.write_bytes(image)

    for path, content in FILES.items():
        if path == "DATA/EMPTY.BIN":
            continue
        ref_path = REFERENCE / path
        ref_path.parent.mkdir(parents=True, exist_ok=True)
        ref_path.write_bytes(content)

    (REFERENCE / "DATA" / "EMPTY.BIN").parent.mkdir(parents=True, exist_ok=True)
    (REFERENCE / "DATA" / "EMPTY.BIN").write_bytes(FILES["DATA/EMPTY.BIN"])

    tools = {
        "self-consistency": "structural-proof",
        "generator": GENERATOR,
    }
    tree = FileTree(source=FileSource(image_path), format="xdvdfs", entries=tuple(entries))
    manifest = canonical_manifest(tree, "game.xiso", sha256_of(image_path), tools)
    (OUT / "expected.manifest.json").write_bytes(manifest)

    print(f"wrote {image_path} ({len(image)} bytes)")
    print("expected.manifest.json generated.")


if __name__ == "__main__":
    main()
