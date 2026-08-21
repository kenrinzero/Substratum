#!/usr/bin/env python3
"""Author the synthetic 3DS RomFS fixture (NORMALIZERS.md row `3ds-romfs`).

Hand-builds a small IVFC-wrapped RomFS region (the decrypted NCCH
`romfs.bin` layer) with real structure throughout:

- level-3 metadata: 0x28 header, directory/file hash-bucket tables with
  the documented GBATEK checksum chains (ROR-5 over parent^0x123456789),
  variable-length directory/file entries with inline UTF-16LE names,
  sibling/child/parent links, and 16-byte-aligned file data;
- IVFC wrapper: 0x5C header (3 level descriptors + header-size field),
  master hash table at 0x60, level-3 data at 0x1000, then the relocated
  level-0/level-1 hash tables after the data (level-1 padded end equals
  the region end), with every hash computed for real —
  master <- L0 <- L1 <- data (partial trailing block zero-padded);
- the declared (virtual) level offsets follow the canonical pre-data
  chain [0, align(l0), align(l0)+align(l1)].

Also writes `level3.bin`, the data-region slice that `ctrtool -t romfs`
consumes as the independent oracle. The expected manifest is authored
from this seedtool's own layout (the xdvdfs pattern); ctrtool's listing
and extraction cross-check paths/sizes/bytes in the tests, and the
staged Cubic Ninja anchor carries the real-media proof.
"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from substratum.contract import FileEntry, FileSource, FileTree, canonical_manifest, sha256_of

GENERATOR = "make_3ds_romfs_fixture v1"
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "fixtures" / "3ds_romfs" / "synthetic"

_BLOCK = 0x1000
_NONE = 0xFFFFFFFF
_HDR_SIZE = 0x5C
_META_HDR = 0x28
_DATA_OFF = 0x1000
_CHK_SEED = 0x123456789

_FILES_README = (
    b"Substratum synthetic 3DS RomFS fixture. "
    b"Authored by seedtools/make_3ds_romfs_fixture.py.\n"
)
DIRS = ["DATA", "DATA/SUB"]  # depth-first after root


def _blob(tag: bytes, size: int) -> bytes:
    out = bytearray()
    h = tag
    while len(out) < size:
        h = hashlib.sha256(h).digest()
        out += h
    return bytes(out[:size])


FILES = [
    ("README.TXT", _FILES_README),
    ("DATA/A.BIN", _blob(b"substratum-3dsromfs-a", _BLOCK)),   # exactly one hash block
    ("DATA/B.BIN", _blob(b"substratum-3dsromfs-b", 2048)),
    ("DATA/EMPTY.BIN", b""),
    ("DATA/SUB/C.DAT", _blob(b"substratum-3dsromfs-c", 500)),  # partial trailing block
]


def _align(n: int, a: int) -> int:
    return n + (-n % a)


def _ror32(v: int, n: int) -> int:
    n &= 31
    return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF


def _checksum(parent_off: int, name_utf16: bytes) -> int:
    chk = (parent_off ^ _CHK_SEED) & 0xFFFFFFFF
    for i in range(0, len(name_utf16), 2):
        chk = (_ror32(chk, 5) ^ name_utf16[i]) & 0xFFFFFFFF
    return chk


def _name_field(name: str) -> bytes:
    raw = name.encode("utf-16-le")
    return struct.pack("<I", len(raw)) + raw + b"\x00" * (-len(raw) % 4)


def _link_siblings(table: bytearray, head_field_off: int, next_field_off: int, new: int) -> None:
    """Append `new` to the chain headed at table[head_field_off]."""
    cur = struct.unpack_from("<I", table, head_field_off)[0]
    if cur == _NONE:
        struct.pack_into("<I", table, head_field_off, new)
        return
    while True:
        nxt = struct.unpack_from("<I", table, cur + next_field_off)[0]
        if nxt == _NONE:
            struct.pack_into("<I", table, cur + next_field_off, new)
            return
        cur = nxt


def build_level3() -> bytes:
    # --- file payloads (16-byte aligned, in FILES order) ---
    data = bytearray()
    spans: dict[str, tuple[int, int]] = {}
    for path, payload in FILES:
        spans[path] = (len(data), len(payload))
        data += payload
        data += b"\x00" * (-len(payload) % 16)

    # --- directory table: root first, then DIRS depth-first ---
    dt = bytearray()
    slots: dict[str, int] = {}
    for name in [""] + DIRS:
        slots[name] = len(dt)
        parent_name = name.rsplit("/", 1)[0] if "/" in name else ""
        parent = slots[parent_name]  # root: its own slot (self-parent)
        dt += struct.pack("<5I", parent, _NONE, _NONE, _NONE, _NONE)
        dt += _name_field(name.rsplit("/", 1)[-1])
    for name in DIRS:
        parent_name = name.rsplit("/", 1)[0] if "/" in name else ""
        _link_siblings(dt, slots[parent_name] + 8, 4, slots[name])  # child +8, sibling +4

    # --- file table (parent, sibling, u64 offset, u64 size, hashNext, name) ---
    ft = bytearray()
    file_slots: dict[str, int] = {}
    for path, _payload in FILES:
        file_slots[path] = len(ft)
        parent_slot = slots[path.rsplit("/", 1)[0] if "/" in path else ""]
        off, size = spans[path]
        ft += struct.pack("<IIQQI", parent_slot, _NONE, off, size, _NONE)
        ft += _name_field(path.rsplit("/", 1)[-1])
    for path, _payload in FILES:
        parent_slot = slots[path.rsplit("/", 1)[0] if "/" in path else ""]
        head_off = parent_slot + 12  # dir entry's first-file field
        cur = struct.unpack_from("<I", dt, head_off)[0]
        if cur == _NONE:
            struct.pack_into("<I", dt, head_off, file_slots[path])
        else:
            while True:
                nxt = struct.unpack_from("<I", ft, cur + 4)[0]
                if nxt == _NONE:
                    struct.pack_into("<I", ft, cur + 4, file_slots[path])
                    break
                cur = nxt

    # --- hash bucket tables (real GBATEK checksum chains) ---
    def buckets(table: bytearray, entries: dict[str, int], hash_next_off: int) -> bytes:
        n = max(4, len(entries))
        n = 1 << (n - 1).bit_length()
        heads = [_NONE] * n
        for ident, off in entries.items():
            base = ident.rsplit("/", 1)[0] if "/" in ident else ""
            name16 = ident.rsplit("/", 1)[-1].encode("utf-16-le")
            chk = _checksum(slots[base], name16)
            if heads[chk % n] == _NONE:
                heads[chk % n] = off
            else:
                head = heads[chk % n]
                while True:
                    nxt = struct.unpack_from("<I", table, head + hash_next_off)[0]
                    if nxt == _NONE:
                        struct.pack_into("<I", table, head + hash_next_off, off)
                        break
                    head = nxt
        return b"".join(struct.pack("<I", h) for h in heads)

    dht = buckets(dt, slots, 0x10)      # dir entry hashNext at +0x10
    fht = buckets(ft, file_slots, 0x18)  # file entry hashNext at +0x18

    # --- level-3 assembly: header, tables, 16-aligned file data ---
    tables_len = _META_HDR + len(dht) + len(dt) + len(fht) + len(ft)
    fdata_off = _align(tables_len, 16)
    header = struct.pack(
        "<10I", _META_HDR, _META_HDR, len(dht),
        _META_HDR + len(dht), len(dt),
        _META_HDR + len(dht) + len(dt), len(fht),
        _META_HDR + len(dht) + len(dt) + len(fht), len(ft),
        fdata_off,
    )
    level3 = header + dht + bytes(dt) + fht + bytes(ft)
    level3 += b"\x00" * (fdata_off - len(level3))
    level3 += bytes(data)
    info = {"fdata_off": fdata_off, "spans": spans}
    return level3, info


def _hash_blocks(blob: bytes, block: int) -> list[bytes]:
    if not blob:
        return [hashlib.sha256(b"\x00" * block).digest()]
    return [
        hashlib.sha256(blob[i : i + block] + b"\x00" * (block - len(blob[i : i + block]))).digest()
        for i in range(0, len(blob), block)
    ]


def build_region() -> tuple[bytes, bytes, dict]:
    level3, info = build_level3()

    l1 = b"".join(_hash_blocks(level3, _BLOCK))       # hashes the data level
    l0 = b"".join(_hash_blocks(l1, _BLOCK))           # hashes L1
    mht = b"".join(_hash_blocks(l0, _BLOCK))          # hashes L0 (already block-padded)

    l0_off = _align(_DATA_OFF + len(level3), _BLOCK)
    l1_off = _align(l0_off + len(l0), _BLOCK)
    region_size = _align(l1_off + len(l1), _BLOCK)

    align_l0 = _align(len(l0), _BLOCK)
    align_l1 = _align(len(l1), _BLOCK)
    declared = (0, align_l0, align_l0 + align_l1)

    header = struct.pack("<III", 0x43465649, 0x00010000, len(mht))
    for off, size in zip(declared, (len(l0), len(l1), len(level3))):
        header += struct.pack("<QQII", off, size, 12, 0)
    header += struct.pack("<II", _HDR_SIZE, 0)  # header-size field + reserved word
    assert len(header) == _HDR_SIZE

    mht_off = _align(_HDR_SIZE, 16)
    region = bytearray(header)
    region += b"\x00" * (mht_off - len(region))
    region += mht
    region += b"\x00" * (_DATA_OFF - len(region))
    region += level3
    region += b"\x00" * (l0_off - len(region))
    region += l0
    region += b"\x00" * (l1_off - len(region))
    region += l1
    region += b"\x00" * (region_size - len(region))
    return bytes(region), level3, info


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    region, level3, info = build_region()
    (OUT / "game.romfs").write_bytes(region)
    (OUT / "level3.bin").write_bytes(level3)

    entries = []
    for path in sorted(set(list(DIRS) + [p for p, _ in FILES])):
        if path in DIRS:
            entries.append(FileEntry(path, "dir", 0, 0))
        else:
            off, size = info["spans"][path]
            entries.append(
                FileEntry(path, "file", _DATA_OFF + info["fdata_off"] + off, size)
            )
    tree = FileTree(source=FileSource(OUT / "game.romfs"), format="3ds-romfs",
                    entries=tuple(entries))
    tools = {
        "generator": GENERATOR,
        "differential": "ctrtool v1.3.0",
        "self-consistency": "structural-proof",
    }
    manifest = canonical_manifest(tree, "game.romfs", sha256_of(OUT / "game.romfs"), tools)
    (OUT / "expected.manifest.json").write_bytes(manifest)
    print(f"wrote game.romfs ({len(region)} bytes) + level3.bin ({len(level3)} bytes) "
          f"+ expected.manifest.json ({len(entries)} entries)")


if __name__ == "__main__":
    main()
