#!/usr/bin/env python3
"""Author the synthetic ZIP fixture (NORMALIZERS.md row `zip`).

Hand-packs a small archive (no zipfile module) so every structural
variant the normalizer must accept is present and byte-controlled:

- STORED and DEFLATE members (incompressible sha256-chain payloads AND
  compressible patterned ones);
- directory entries (`DATA/`, `DATA/SUB/`) and a 0-byte member;
- one member written "streaming-style" with the data-descriptor flag
  (bit 3): zeroed local sizes + `PK\x07\x08` descriptor after the data,
  real sizes in the central directory;
- one ZIP64 member: 0xFFFFFFFF sentinels in both headers + ZIP64 extra
  fields carrying the true values (small payloads exercise the parse
  path without a 4 GiB fixture);
- a ZIP64 end-of-central-directory record + locator in front of the
  plain EOCD (whose cd_size/cd_offset are sentinels), plus an EOCD
  archive comment.

Central-directory order is deliberately NOT path-sorted (README before
BOOT/, BIG/ last) so a parser that confuses CD order with the spool
layout cannot pass the gate.

This tool writes ONLY `game.zip`. The expected manifest is authored from
7-Zip's independent listing and the reference bytes come from `7z x`
(DESIGN §3 two-party rule; see tests/test_zip.py).
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from pathlib import Path

GENERATOR = "make_zip_fixture v1"
ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "fixtures" / "zip" / "synthetic"

_DOS_TIME = 0x6000  # 12:00:00
_DOS_DATE = 0x3421  # 2026-01-01
_METHOD_STORED = 0
_METHOD_DEFLATE = 8
_FLAG_DESCRIPTOR = 0x0008
_ZIP64_SENTINEL32 = 0xFFFFFFFF


def _blob(tag: bytes, size: int) -> bytes:
    """Deterministic pseudo-random payload (sha256 chain)."""
    out = bytearray()
    h = tag
    while len(out) < size:
        h = hashlib.sha256(h).digest()
        out += h
    return bytes(out[:size])


def _deflate(data: bytes) -> bytes:
    comp = zlib.compressobj(9, zlib.DEFLATED, -15)
    return comp.compress(data) + comp.flush()


class _Spec:
    """One member to serialize: name (with trailing '/' for dirs), payload,
    method, per-member structural quirks."""

    def __init__(self, name: str, data: bytes, *, method: int = _METHOD_DEFLATE,
                 descriptor: bool = False, zip64: bool = False, is_dir: bool = False) -> None:
        self.name = name
        self.data = data
        self.method = _METHOD_STORED if is_dir else method
        self.descriptor = descriptor
        self.zip64 = zip64
        self.is_dir = is_dir

    @property
    def crc(self) -> int:
        return zlib.crc32(self.data) & 0xFFFFFFFF


SPECS: list[_Spec] = [
    _Spec("DATA/", b"", is_dir=True),
    _Spec("README.TXT", b"Substratum synthetic ZIP fixture. Authored by seedtools/make_zip_fixture.py.\n",
          method=_METHOD_STORED),
    _Spec("BOOT/APP.BIN", _blob(b"substratum-zip-app", 4096)),
    _Spec("DATA/A.BIN", bytes(range(256))),
    _Spec("DATA/B.BIN", b"\x00\x01\x02\x03" * 512, method=_METHOD_STORED),
    _Spec("DATA/EMPTY.BIN", b""),
    _Spec("DATA/SUB/", b"", is_dir=True),
    _Spec("DATA/SUB/C.DAT", _blob(b"substratum-zip-c", 512), descriptor=True),
    _Spec("BIG/Z64.BIN", _blob(b"substratum-zip-z64", 1024), zip64=True),
]


def _zip64_extra_cd(spec: _Spec, local_offset: int) -> bytes:
    # ZIP64 extra in the central directory: usize, csize, local offset —
    # only the fields whose base header carries the sentinel.
    return struct.pack("<HH", 0x0001, 24) + struct.pack(
        "<QQQ", len(spec.data), len(_payload(spec)), local_offset
    )


def _zip64_extra_local(spec: _Spec) -> bytes:
    # ZIP64 extra in the local header: usize, csize only.
    return struct.pack("<HH", 0x0001, 16) + struct.pack(
        "<QQ", len(spec.data), len(_payload(spec))
    )


def _payload(spec: _Spec) -> bytes:
    if spec.is_dir or spec.method == _METHOD_STORED:
        return spec.data
    return _deflate(spec.data)


def build_archive() -> bytes:
    out = bytearray()
    offsets: list[int] = []

    # --- local records ---
    for spec in SPECS:
        name = spec.name.encode("ascii")
        payload = _payload(spec)
        flags = 0
        if spec.descriptor:
            flags |= _FLAG_DESCRIPTOR
        crc = 0 if spec.descriptor else spec.crc
        csize = _ZIP64_SENTINEL32 if spec.zip64 else len(payload)
        usize = _ZIP64_SENTINEL32 if spec.zip64 else len(spec.data)
        extra = _zip64_extra_local(spec) if spec.zip64 else b""
        offsets.append(len(out))
        out += struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,           # local file header
            45 if spec.zip64 else 20,
            flags,
            spec.method,
            _DOS_TIME,
            _DOS_DATE,
            crc,
            csize,
            usize,
            len(name),
            len(extra),
        )
        out += name + extra + payload
        if spec.descriptor:
            out += struct.pack(
                "<IIII", 0x08074B50, spec.crc, len(payload), len(spec.data)
            )

    # --- central directory ---
    cd_start = len(out)
    for spec, local_offset in zip(SPECS, offsets):
        name = spec.name.encode("ascii")
        payload = _payload(spec)
        flags = 0
        if spec.descriptor:
            flags |= _FLAG_DESCRIPTOR
        csize = _ZIP64_SENTINEL32 if spec.zip64 else len(payload)
        usize = _ZIP64_SENTINEL32 if spec.zip64 else len(spec.data)
        offset = _ZIP64_SENTINEL32 if spec.zip64 else local_offset
        extra = _zip64_extra_cd(spec, local_offset) if spec.zip64 else b""
        ext_attr = 0x10 if spec.is_dir else 0x20
        out += struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,           # central directory file header
            20,                   # version made by (MS-DOS)
            45 if spec.zip64 else 20,
            flags,
            spec.method,
            _DOS_TIME,
            _DOS_DATE,
            spec.crc,
            csize,
            usize,
            len(name),
            len(extra),
            0,                    # file comment length
            0,                    # disk number start
            0,                    # internal attributes
            ext_attr,
            offset,
        )
        out += name + extra
    cd_size = len(out) - cd_start

    # --- ZIP64 EOCD + locator + plain EOCD ---
    z64_eocd_offset = len(out)
    out += struct.pack(
        "<IQHHIIQQQQ",
        0x06064B50,           # zip64 end of central directory record
        44,                   # size of remainder of this record
        20, 45,               # version made by / needed
        0, 0,                 # this disk / disk with CD
        len(SPECS),           # entries on this disk
        len(SPECS),           # entries total
        cd_size,
        cd_start,
    )
    out += struct.pack(
        "<IIQI",
        0x07064B50,           # zip64 EOCD locator
        0,                    # disk with the zip64 EOCD
        z64_eocd_offset,
        1,                    # total disks
    )
    comment = b"substratum synthetic zip fixture"
    out += struct.pack(
        "<IHHHHIIH",
        0x06054B50,           # end of central directory record
        0, 0,                 # this disk / disk with CD
        len(SPECS),           # entries on this disk
        len(SPECS),           # entries total
        _ZIP64_SENTINEL32,    # cd size (zip64 sentinel)
        _ZIP64_SENTINEL32,    # cd offset (zip64 sentinel)
        len(comment),
    )
    out += comment
    return bytes(out)


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    archive = build_archive()
    path = OUT / "game.zip"
    path.write_bytes(archive)
    total = sum(len(s.data) for s in SPECS if not s.is_dir)
    print(f"wrote {path} ({len(archive)} bytes, {len(SPECS)} members, "
          f"{total} uncompressed payload bytes)")
    print("expected.manifest.json is NOT written here — author it from the "
          "7-Zip listing (two-party rule).")


if __name__ == "__main__":
    main()
