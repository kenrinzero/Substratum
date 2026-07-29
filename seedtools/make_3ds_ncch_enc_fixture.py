#!/usr/bin/env python3
"""Author the committed synthetic 3DS encrypted-NCCH fixture.

Usage:
    uv run python seedtools/make_3ds_ncch_enc_fixture.py

A committed fixture that the production ctrtool (retail keys compiled in) can
decrypt is NOT authorable without retail key material: encrypting an NCCH with
the standard key requires the retail AES key, which this repo never handles.
3dstool's ``--fixed-key`` uses a debug key that ctrtool cannot decrypt, and the
ExeFS sub-layer's separate crypto diverges between the two tools even under dev
keys. (Recorded finding, 2026-07-29.)

The committed fixture therefore exercises the layers that are testable without
retail bytes: the NCCH header shape, the region table, and the downstream
``three_ds_ncch`` composition over a *decrypted* (NoCrypto) NCCH. Actual
decryption + the genuine two-party differential (ctrtool vs 3dstool, both using
retail keys) is carried by the retail anchor on Biohazard — The Mercenaries 3D
— whose test is skip-if-absent and proven end-to-end.

This seedtool writes a small NoCrypto NCCH with known region payloads. The
normalizer's encrypted path is then unit-tested by:

  * structural-red cases that mutate the synthetic's header to declare
    encryption / non-standard crypto / seed, asserting the normalizer refuses
    them before any ctrtool call; and
  * the retail anchor, which exercises the real decrypt path.

Runtime is stdlib-only; no vendored tool is invoked here.
"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "fixtures" / "3ds_ncch_enc" / "synthetic"

# NCCH header constants (mirror three_ds_ncch / three_ds_ncch_enc).
_HEADER_SIZE = 0x200
_MAGIC_OFFSET = 0x100
_ACCESS_DESCRIPTOR_SIZE = 0x400
_NO_ENCRYPTION = 1 << 2

_EXHEADER_SIZE = 0x400
_PLAIN_OFFSET = 0xA00
_PLAIN_SIZE = 0x200
_EXEFS_OFFSET = 0xC00
_EXEFS_SIZE = 0x400
_ROMFS_OFFSET = 0x1000
_ROMFS_SIZE = 0x400
_TOTAL_SIZE = _ROMFS_OFFSET + _ROMFS_SIZE  # 0x1400


def _build_plain_ncch() -> bytes:
    """Build a small NoCrypto NCCH exercising every region type.

    Region payloads are deterministic and documented here so the expected
    manifest and any plaintext check are derivable from this seedtool's shape,
    not from running the normalizer (DESIGN §3 one-party rule).
    """
    img = bytearray(_TOTAL_SIZE)
    struct.pack_into("<I", img, 0x000, 0x10004)  # RSA-2048-SHA256 sig type (stub)
    img[_MAGIC_OFFSET : _MAGIC_OFFSET + 4] = b"NCCH"
    struct.pack_into("<I", img, 0x104, _TOTAL_SIZE // 0x200)  # content size units
    struct.pack_into("<Q", img, 0x108, 0x0004000000000001)  # title id
    img[0x110 : 0x112] = b"ZZ"
    struct.pack_into("<H", img, 0x112, 2)  # format version 2
    struct.pack_into("<Q", img, 0x118, 0x0004000000000001)
    img[0x150 : 0x160] = b"CTR-P-TEST" + b"\x00" * 6

    img[0x200 : 0x600] = b"E" * _EXHEADER_SIZE  # extended header
    img[0x600 : 0xA00] = b"A" * _ACCESS_DESCRIPTOR_SIZE  # access descriptor
    img[_PLAIN_OFFSET : _PLAIN_OFFSET + _PLAIN_SIZE] = b"P" * _PLAIN_SIZE
    img[_EXEFS_OFFSET : _EXEFS_OFFSET + _EXEFS_SIZE] = b"L" * 0x200 + b"X" * 0x200
    img[_ROMFS_OFFSET : _ROMFS_OFFSET + _ROMFS_SIZE] = b"R" * 0x200 + b"r" * 0x200

    # declared protected hashes (authoritative — three_ds_ncch validates them)
    img[0x160 : 0x180] = hashlib.sha256(bytes(img[0x200 : 0x600])).digest()
    struct.pack_into("<I", img, 0x180, _EXHEADER_SIZE)
    img[0x18C] = 1
    img[0x18D] = 3
    img[0x18E] = 0
    img[0x18F] = _NO_ENCRYPTION  # NoCrypto — this is a decrypted image
    struct.pack_into("<II", img, 0x190, _PLAIN_OFFSET // 0x200, _PLAIN_SIZE // 0x200)
    struct.pack_into(
        "<III", img, 0x1A0, _EXEFS_OFFSET // 0x200, _EXEFS_SIZE // 0x200, _EXEFS_SIZE // 0x200
    )
    struct.pack_into(
        "<III", img, 0x1B0, _ROMFS_OFFSET // 0x200, _ROMFS_SIZE // 0x200, _ROMFS_SIZE // 0x200
    )
    img[0x1C0 : 0x1E0] = hashlib.sha256(bytes(img[_EXEFS_OFFSET : _EXEFS_OFFSET + _EXEFS_SIZE])).digest()
    img[0x1E0 : 0x200] = hashlib.sha256(bytes(img[_ROMFS_OFFSET : _ROMFS_OFFSET + _ROMFS_SIZE])).digest()
    return bytes(img)


def main() -> None:
    if len(sys.argv) > 1:
        raise SystemExit(__doc__)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    image = _build_plain_ncch()
    (OUTPUT / "decrypted.ncch").write_bytes(image)

    digest = hashlib.sha256(image).hexdigest()
    print(f"wrote {OUTPUT / 'decrypted.ncch'} ({len(image)} bytes, sha256 {digest})")
    print(
        "regions: extendedheader.bin@0x200/0x800 plain.bin@0xa00/0x200 "
        "exefs.bin@0xc00/0x400 romfs.bin@0x1000/0x400 (NoCrypto, decrypted)"
    )
    print(
        "\nThis is a DECRYPTED NoCrypto NCCH — it exercises the composition and "
        "structural paths. The encrypted decrypt path + two-party differential "
        "is carried by the retail Biohazard anchor (skip-if-absent)."
    )


if __name__ == "__main__":
    main()
