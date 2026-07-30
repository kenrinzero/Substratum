#!/usr/bin/env python3
"""Author the committed synthetic New3DS-9.6 encrypted-NCCH fixture.

Usage:
    uv run python seedtools/make_3ds_ncch_enc_96_fixture.py

Unlike the standard-crypto seedtool (which can only author a *decrypted* NCCH
because encrypting needs retail keys + ctrtool), the 9.6 path is pure-Python:
``substratum/_aes.py`` has both the AES-CTR primitive and the key generator, so
this seedtool encrypts a known-plaintext NCCH with **generated test keyX/keyY
pairs** (NOT retail slot0x2C/0x1B values — arbitrary test values, like the Wii
partition test key) and the production normalizer decrypts it back. That gives a
committed fixture that exercises the *real* decrypt path end-to-end, including
the two-key ExeFS split — a stronger synthetic than the standard unit could do.

What commits:
  - ``fixtures/3ds_ncch_enc_96/synthetic/encrypted.ncch`` — the encrypted image.
  - ``fixtures/3ds_ncch_enc_96/synthetic/test_keyset.txt`` — the two test keyX
    values (``slot0x2CKeyX`` + ``slot0x1BKeyX``) under the generated test keyY,
    so the normalizer loads them exactly as it loads the operator keyset. These
    are TEST values with no relationship to retail keys; publishing them is the
    whole point (they are the fixture's key material).

The seedtool also re-derives the protected hashes from the plaintext so the
downstream ``three_ds_ncch`` gate validates the decrypt. The two-key model
(docs/3DS-KEYED-WORK.md): exheader + ExeFS superblock + ExeFS tail encrypt with
Key0 (slot0x2C); the first ExeFS file (``.code``) + RomFS encrypt with Key1
(slot0x1B). The ExeFS is one continuous CTR stream whose key switches mid-stream.

Runtime is stdlib-only; no vendored tool is invoked here.
"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from substratum._aes import aes128_ctr_xor, normalkey_from_keyxy

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "fixtures" / "3ds_ncch_enc_96" / "synthetic"

# NCCH header constants (mirror three_ds_ncch / three_ds_ncch_enc_96).
_HEADER_SIZE = 0x200
_MAGIC_OFFSET = 0x100
_ACCESS_DESCRIPTOR_SIZE = 0x400
_EXHEADER_SIZE = 0x400
_EXEFS_SUPERBLOCK_SIZE = 0x200

# Region layout (NCCH-block = 0x200 units in the region table). Non-overlapping,
# each region 0x200-aligned, tiling [0, _TOTAL_SIZE) with no gaps past the end.
_PLAIN_OFFSET = 0xA00
_PLAIN_SIZE = 0x200
_LOGO_OFFSET = 0xC00
_LOGO_SIZE = 0x2000
_EXEFS_OFFSET = 0x2C00
# ExeFS: 0x200 superblock + .code (0x400) + one more file (0x200) to exercise
# the two-key split (Key0 superblock, Key1 .code, Key0 tail).
_EXEFS_CODE_SIZE = 0x400
_EXEFS_TAIL_SIZE = 0x200
_EXEFS_SIZE = _EXEFS_SUPERBLOCK_SIZE + _EXEFS_CODE_SIZE + _EXEFS_TAIL_SIZE  # 0x800
_ROMFS_OFFSET = 0x3400
_ROMFS_SIZE = 0x600
_TOTAL_SIZE = _ROMFS_OFFSET + _ROMFS_SIZE  # 0x3A00

# Test keyX/keyY values — arbitrary, generated, NOT retail. The committed test
# keyset carries slot0x2CKeyX + slot0x1BKeyX; the keyY is the NCCH signature,
# which the fixture sets below.
_TEST_KEYX_OLD = bytes.fromhex("00112233445566778899aabbccddeeff")  # slot0x2C
_TEST_KEYX_NEW = bytes.fromhex("ffeeddccbbaa99887766554433221100")  # slot0x1B
_TEST_KEYY = bytes.fromhex("0123456789abcdeffedcba9876543210")  # sig[:16]

# Region magic bytes for the version-2 NCCH AES counter (exheader=1, exefs=2,
# romfs=3). Counter block 0 = titleId[::-1] + magic + 7 zero bytes.
_MAGIC_EXHEADER = 1
_MAGIC_EXEFS = 2
_MAGIC_ROMFS = 3
_TEST_TITLE_ID = (0x0004000000000001).to_bytes(8, "little")


def _counter(magic: int, block_index: int = 0) -> bytes:
    counter = bytearray(16)
    counter[0:8] = _TEST_TITLE_ID[::-1]
    counter[8] = magic
    c = int.from_bytes(counter, "big") + block_index
    return (c & ((1 << 128) - 1)).to_bytes(16, "big")


def _build_plaintext_ncch() -> bytes:
    """Build the plaintext NoCrypto NCCH with known region payloads."""
    img = bytearray(_TOTAL_SIZE)
    img[0:16] = _TEST_KEYY  # signature[:16] is the keyY
    img[_MAGIC_OFFSET : _MAGIC_OFFSET + 4] = b"NCCH"
    struct.pack_into("<I", img, 0x104, _TOTAL_SIZE // 0x200)  # content size units
    struct.pack_into("<Q", img, 0x108, 0x0004000000000001)  # title id (LE)
    struct.pack_into("<H", img, 0x112, 2)  # format version 2
    struct.pack_into("<Q", img, 0x118, 0x0004000000000001)  # program id

    img[0x200 : 0x600] = b"E" * _EXHEADER_SIZE  # extended header
    img[0x600 : 0xA00] = b"A" * _ACCESS_DESCRIPTOR_SIZE  # access descriptor
    img[_PLAIN_OFFSET : _PLAIN_OFFSET + _PLAIN_SIZE] = b"P" * _PLAIN_SIZE
    img[_LOGO_OFFSET : _LOGO_OFFSET + _LOGO_SIZE] = b"L" * _LOGO_SIZE

    # ExeFS superblock: 10 file headers (name[8] + offset u32 + size u32).
    # File 0 = ".code" (offset 0, size _EXEFS_CODE_SIZE); file 1 = "tail".
    sb = bytearray(_EXEFS_SUPERBLOCK_SIZE)
    sb[0:8] = b".code\x00\x00\x00"
    struct.pack_into("<I", sb, 0x08, 0)  # offset (after superblock)
    struct.pack_into("<I", sb, 0x0C, _EXEFS_CODE_SIZE)  # size
    sb[0x10:0x18] = b"tail\x00\x00\x00\x00"
    struct.pack_into("<I", sb, 0x18, _EXEFS_CODE_SIZE)  # offset
    struct.pack_into("<I", sb, 0x1C, _EXEFS_TAIL_SIZE)  # size
    img[_EXEFS_OFFSET : _EXEFS_OFFSET + _EXEFS_SUPERBLOCK_SIZE] = sb
    code_off = _EXEFS_OFFSET + _EXEFS_SUPERBLOCK_SIZE
    img[code_off : code_off + _EXEFS_CODE_SIZE] = b"C" * _EXEFS_CODE_SIZE
    tail_off = code_off + _EXEFS_CODE_SIZE
    img[tail_off : tail_off + _EXEFS_TAIL_SIZE] = b"T" * _EXEFS_TAIL_SIZE

    img[_ROMFS_OFFSET : _ROMFS_OFFSET + _ROMFS_SIZE] = b"R" * _ROMFS_SIZE

    # Region table (offset/size/protected-hashsize in 0x200-block units).
    struct.pack_into("<I", img, 0x180, _EXHEADER_SIZE)
    struct.pack_into("<II", img, 0x190, _PLAIN_OFFSET // 0x200, _PLAIN_SIZE // 0x200)
    struct.pack_into("<II", img, 0x198, _LOGO_OFFSET // 0x200, _LOGO_SIZE // 0x200)
    struct.pack_into(
        "<III",
        img,
        0x1A0,
        _EXEFS_OFFSET // 0x200,
        _EXEFS_SIZE // 0x200,
        _EXEFS_SUPERBLOCK_SIZE // 0x200,  # protected hashsize (superblock only)
    )
    struct.pack_into(
        "<III",
        img,
        0x1B0,
        _ROMFS_OFFSET // 0x200,
        _ROMFS_SIZE // 0x200,
        _ROMFS_SIZE // 0x200,  # full romfs protected
    )
    # Declared protected hashes (authoritative — three_ds_ncch validates these).
    img[0x160 : 0x180] = hashlib.sha256(bytes(img[0x200 : 0x600])).digest()
    img[0x130 : 0x150] = hashlib.sha256(
        bytes(img[_LOGO_OFFSET : _LOGO_OFFSET + _LOGO_SIZE])
    ).digest()
    img[0x1C0 : 0x1E0] = hashlib.sha256(
        bytes(img[_EXEFS_OFFSET : _EXEFS_OFFSET + _EXEFS_SUPERBLOCK_SIZE])
    ).digest()
    img[0x1E0 : 0x200] = hashlib.sha256(
        bytes(img[_ROMFS_OFFSET : _ROMFS_OFFSET + _ROMFS_SIZE])
    ).digest()

    # Flags: ncchflag[3]=0x0B (9.6), NoCrypto CLEAR, seed bit CLEAR.
    img[0x188 : 0x190] = bytes([0x00, 0x00, 0x00, 0x0B, 0x00, 0x03, 0x00, 0x00])
    img[0x18E] = 0  # block-size log (block = 0x200)
    return bytes(img)


def _encrypt_two_key(plain: bytes) -> bytes:
    """Encrypt the plaintext NCCH's regions with the two-key model."""
    key0 = normalkey_from_keyxy(_TEST_KEYX_OLD, _TEST_KEYY)
    key1 = normalkey_from_keyxy(_TEST_KEYX_NEW, _TEST_KEYY)
    img = bytearray(plain)

    # Extended header region [0x200, 0xA00): Key0.
    exh = img[0x200 : 0xA00]
    img[0x200 : 0xA00] = aes128_ctr_xor(key0, _counter(_MAGIC_EXHEADER), exh)

    # ExeFS: one continuous CTR stream, key switches mid-stream.
    exefs = img[_EXEFS_OFFSET : _EXEFS_OFFSET + _EXEFS_SIZE]
    enc = bytearray()
    # Key0 superblock [0, 0x200).
    enc += aes128_ctr_xor(
        key0, _counter(_MAGIC_EXEFS, 0), exefs[0:_EXEFS_SUPERBLOCK_SIZE]
    )
    # Key1 .code [0x200, 0x200+code).
    blk_start = _EXEFS_SUPERBLOCK_SIZE // 16
    code_end = _EXEFS_SUPERBLOCK_SIZE + _EXEFS_CODE_SIZE
    enc += aes128_ctr_xor(
        key1, _counter(_MAGIC_EXEFS, blk_start), exefs[_EXEFS_SUPERBLOCK_SIZE:code_end]
    )
    # Key0 tail.
    blk_rest = code_end // 16
    enc += aes128_ctr_xor(key0, _counter(_MAGIC_EXEFS, blk_rest), exefs[code_end:])
    img[_EXEFS_OFFSET : _EXEFS_OFFSET + _EXEFS_SIZE] = enc

    # RomFS: Key1.
    romfs = img[_ROMFS_OFFSET : _ROMFS_OFFSET + _ROMFS_SIZE]
    img[_ROMFS_OFFSET : _ROMFS_OFFSET + _ROMFS_SIZE] = aes128_ctr_xor(
        key1, _counter(_MAGIC_ROMFS), romfs
    )
    return bytes(img)


def _write_test_keyset() -> bytes:
    """Write the committed test keyset (the two test keyX values)."""
    lines = [
        ":AES",
        f"slot0x2CKeyX={_TEST_KEYX_OLD.hex()}",
        f"slot0x1BKeyX={_TEST_KEYX_NEW.hex()}",
        "",
    ]
    text = "\n".join(lines)
    return text.encode("ascii")


def main() -> None:
    if len(sys.argv) > 1:
        raise SystemExit(__doc__)
    OUTPUT.mkdir(parents=True, exist_ok=True)
    plain = _build_plaintext_ncch()
    enc = _encrypt_two_key(plain)

    (OUTPUT / "encrypted.ncch").write_bytes(enc)
    (OUTPUT / "test_keyset.txt").write_bytes(_write_test_keyset())

    # Sanity: the plaintext's protected hashes are the decrypt oracle.
    print(f"wrote {OUTPUT / 'encrypted.ncch'} ({len(enc)} bytes)")
    print(f"wrote {OUTPUT / 'test_keyset.txt'} (test keyX: slot0x2C + slot0x1B)")
    print(
        "regions: exheader@0x200(Key0) plain@0xa00 logo@0x20800 "
        f"exefs@{_EXEFS_OFFSET:#x}(Key0/Key1/Key0 split) romfs@{_ROMFS_OFFSET:#x}(Key1)"
    )
    print(
        "\nThis is a real ENCRYPTED 9.6 NCCH — the normalizer decrypts it back "
        "via pure-Python AES-CTR with the two committed test keyX values. The "
        "FE Warriors retail anchor carries the on-retail-bytes proof."
    )


if __name__ == "__main__":
    main()
