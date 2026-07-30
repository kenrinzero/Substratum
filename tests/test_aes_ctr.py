"""Gate tests for the AES-128-CTR mode and the 3DS key generator in
``substratum._aes``.

Two proof pillars (docs/3DS-PURE-PYTHON-AES-CTR-PLAN.md, Session A):

1. **CTR correctness (NIST anchor):** ``aes128_ctr_xor`` is validated against
   the NIST SP 800-38A Appendix F.5.1 AES-128-CTR vectors — an anchor entirely
   independent of any 3DS fixture. This is the load-bearing crypto proof, the
   same posture the Wii CBC path takes (NIST F.2.1 in test_wii_partition.py).

2. **Key-generator self-consistency:** the 3DS hardware key generator is a pure
   bit-rotation + add construction; it is proven by (a) rotation identities and
   (b) a CTR round-trip — a known keyX/keyY → normalkey → CTR-encrypt →
   CTR-decrypt round-trip on arbitrary plaintext. The normal-key's *absolute*
   correctness is proven downstream by the New3DS 9.6 retail proof (Session B),
   where the NCCH protected-hash gate is the oracle (3dstool itself cannot
   second-party 9.6). The constant C1 and the ROL-87 rotation are pinned from
   ``dnasdw/3dstool`` source in the implementation; these tests assert the
   documented identities that keep that pin honest.

These tests are crypto-unit tests, not normalizer gate runs — they do not touch
fixtures, manifests, or retail bytes.
"""

from __future__ import annotations

import os
import secrets

from substratum._aes import (
    _MASK128,
    _rol128,
    _ror128,
    aes128_ctr_xor,
    normalkey_from_keyxy,
)

# --------------------------------------------------------------------------
# NIST SP 800-38A Appendix F.5.1 — AES-128-CTR example vectors.
#
# The vectors are transcribed from NIST SP 800-38A (Addendum: Example Vectors),
# Appendix F.5.1 (CTR-AES128.Encrypt). They are the independent correctness
# anchor for ``aes128_ctr_xor``, authored from the NIST publication, NOT derived
# from the code under test. The initial counter and four plaintext/ciphertext
# blocks are exactly as NIST publishes them.
# --------------------------------------------------------------------------
_NIST_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
_NIST_COUNTER0 = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
_NIST_PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"  # block 1
    "ae2d8a571e03ac9c9eb76fac45af8e51"  # block 2
    "30c81c46a35ce411e5fbc1191a0a52ef"  # block 3
    "f69f2445df4f9b17ad2b417be66c3710"  # block 4
)
_NIST_CIPHERTEXT = bytes.fromhex(
    "874d6191b620e3261bef6864990db6ce"  # block 1 (counter f0...ff)
    "9806f66b7970fdff8617187bb9fffdff"  # block 2 (counter f1...00)
    "5ae4df3edbd5d35e5b4f09020db03eab"  # block 3 (counter f2...01)
    "1e031dda2fbe03d1792170a0f3009cee"  # block 4 (counter f3...02)
)


def test_nist_ctr_encrypt_matches_published_vectors():
    """The CTR keystream XOR must reproduce NIST F.5.1 ciphertext exactly."""
    out = aes128_ctr_xor(_NIST_KEY, _NIST_COUNTER0, _NIST_PLAINTEXT)
    assert out == _NIST_CIPHERTEXT


def test_nist_ctr_decrypt_round_trips():
    """CTR is symmetric: decrypt is the same XOR, and recovers the plaintext."""
    out = aes128_ctr_xor(_NIST_KEY, _NIST_COUNTER0, _NIST_CIPHERTEXT)
    assert out == _NIST_PLAINTEXT


def test_nist_ctr_first_block_independent_of_length():
    """The first 16-byte block is the keystream for counter0 XOR plaintext,
    regardless of total input length — proves block independence (no chaining).
    """
    full = aes128_ctr_xor(_NIST_KEY, _NIST_COUNTER0, _NIST_PLAINTEXT[:16])
    assert full == _NIST_CIPHERTEXT[:16]


def test_ctr_handles_unaligned_tail():
    """A non-block-multiple input must decrypt correctly; the final keystream
    block is truncated, not padded."""
    # Take the first 40 bytes (2 full blocks + 8-byte tail) of the NIST stream.
    n = 40
    out = aes128_ctr_xor(_NIST_KEY, _NIST_COUNTER0, _NIST_PLAINTEXT[:n])
    assert out == _NIST_CIPHERTEXT[:n]


def test_ctr_empty_input_returns_empty():
    assert aes128_ctr_xor(_NIST_KEY, _NIST_COUNTER0, b"") == b""


def test_ctr_rejects_bad_key_and_counter():
    import pytest

    with pytest.raises(ValueError):
        aes128_ctr_xor(b"short", _NIST_COUNTER0, _NIST_PLAINTEXT[:16])
    with pytest.raises(ValueError):
        aes128_ctr_xor(_NIST_KEY, b"short", _NIST_PLAINTEXT[:16])


# --------------------------------------------------------------------------
# 128-bit rotation primitives — the key generator's arithmetic core.
# --------------------------------------------------------------------------

def test_rotation_identity_inverse():
    """rol and ror are inverses: rol(ror(x, n), n) == x over 128 bits."""
    for _ in range(256):
        x = secrets.randbits(128)
        n = secrets.randbelow(128)
        assert _rol128(_ror128(x, n), n) == x & _MASK128
        assert _ror128(_rol128(x, n), n) == x & _MASK128


def test_rotation_zero_and_full_are_identity():
    """ROL/ROR by 0 or 128 leaves a 128-bit value unchanged."""
    x = secrets.randbits(128)
    assert _rol128(x, 0) == x & _MASK128
    assert _rol128(x, 128) == x & _MASK128
    assert _ror128(x, 0) == x & _MASK128


def test_rol87_equals_ror41():
    """3dstool's final rotate is ROL 87; 3DBrew writes it as ROR 41. They must
    agree because 41 + 87 == 128. This is the identity that keeps the plan's
    ROR-41 formula and 3dstool's ROL-87 source describing the same operation.
    """
    for _ in range(256):
        x = secrets.randbits(128)
        assert _rol128(x, 87) == _ror128(x, 41)


# --------------------------------------------------------------------------
# 3DS hardware key generator — self-consistency via round-trip.
# --------------------------------------------------------------------------

def _romforge_keygen(keyx: bytes, keyy: bytes) -> bytes:
    """Verbatim Python port of RomForge's ``3DS.Core/Crypto/KeySlot.cs``
    ``TryGenerateNormalKey`` (sinjunyoung/RomForge, independent of 3dstool's
    bignum path). Reproduced here as an *independent second implementation* of
    the key generator so a fuzz differential against ``normalkey_from_keyxy``
    is a genuine two-party check: RomForge works on raw byte arrays with
    explicit carry propagation, while the module under test works on a single
    big-endian int — so a bug in C1, the rotation amount/direction, the add
    endianness, or an x-vs-add confusion would diverge here.

    Steps (KeySlot.cs): step1 = Lrot128(KeyX, 2); step2 = Xor128(step1, KeyY);
    step3 = Add128(step2, GeneratorConstant); NormalKey = Lrot128(step3, 87).
    """

    def lrot128(data: bytes, rot: int) -> bytes:
        rot %= 128
        result = bytearray(16)
        byte_shift, bit_shift = divmod(rot, 8)
        for i in range(16):
            src = (i + byte_shift) % 16
            nxt = (src + 1) % 16
            if bit_shift == 0:
                result[i] = data[src]
            else:
                result[i] = (data[src] << bit_shift | data[nxt] >> (8 - bit_shift)) & 0xFF
        return bytes(result)

    def xor128(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    def add128(a: bytes, b: bytes) -> bytes:
        # RomForge: carry propagates from i=15 (LSB) up to i=0 (big-endian).
        result = bytearray(16)
        carry = 0
        for i in range(15, -1, -1):
            total = a[i] + b[i] + carry
            result[i] = total & 0xFF
            carry = total >> 8
        return bytes(result)

    c = bytes.fromhex("1ff9e9aac5fe0408024591dc5d52768a")
    step1 = lrot128(keyx, 2)
    step2 = xor128(step1, keyy)
    step3 = add128(step2, c)
    return lrot128(step3, 87)


def test_normalkey_matches_independent_reference_implementation():
    """Two-party differential: ``normalkey_from_keyxy`` (int-based) must agree
    with a verbatim port of RomForge's byte-array KeySlot.cs over many random
    keyX/keyY pairs. This is the strongest correctness proof available in
    Session A without retail material — it exercises the C1 constant, the ROL 2
    and ROL 87 rotations, and the 128-bit modular add against an independently
    written implementation of the same published spec.
    """
    for _ in range(512):
        keyx = secrets.token_bytes(16)
        keyy = secrets.token_bytes(16)
        assert normalkey_from_keyxy(keyx, keyy) == _romforge_keygen(keyx, keyy)


def test_normalkey_matches_reference_for_all_zero_and_all_one():
    """Boundary inputs that stress the carry/rotation paths."""
    for boundary in (b"\x00" * 16, b"\xff" * 16):
        for keyy in (b"\x00" * 16, b"\xff" * 16, boundary):
            assert normalkey_from_keyxy(boundary, keyy) == _romforge_keygen(
                boundary, keyy
            )


def test_normalkey_round_trips_through_ctr():
    """A keyX/keyY-derived normalkey must act as a valid AES-128 key: encrypt
    then decrypt arbitrary plaintext through CTR and recover it. Proves the
    generator emits a 16-byte value usable as a key, end-to-end, without any
    retail key material. (Absolute normalkey correctness is proven by the 9.6
    retail protected-hash gate in Session B; this proves the round-trip wiring.)
    """
    keyx = secrets.token_bytes(16)
    keyy = secrets.token_bytes(16)
    normalkey = normalkey_from_keyxy(keyx, keyy)
    assert len(normalkey) == 16
    counter = secrets.token_bytes(16)
    plaintext = os.urandom(1000)  # non-block-aligned on purpose
    ciphertext = aes128_ctr_xor(normalkey, counter, plaintext)
    recovered = aes128_ctr_xor(normalkey, counter, ciphertext)
    assert recovered == plaintext


def test_normalkey_is_deterministic():
    """Same keyX/keyY must always yield the same normalkey (the hardware result
    is fixed)."""
    keyx = bytes.fromhex("00112233445566778899aabbccddeeff")
    keyy = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    assert normalkey_from_keyxy(keyx, keyy) == normalkey_from_keyxy(keyx, keyy)


def test_normalkey_rejects_wrong_lengths():
    import pytest

    with pytest.raises(ValueError):
        normalkey_from_keyxy(b"short", b"0123456789abcdef")
    with pytest.raises(ValueError):
        normalkey_from_keyxy(b"0123456789abcdef", b"short")


def test_normalkey_known_vector_round_trips():
    """A drift-pin, not an independent anchor: feed a fixed keyX/keyY, derive a
    normalkey, and confirm it round-trips through a fixed counter for a fixed
    plaintext. The asserted normalkey + ciphertext were generated by THIS code
    on a known-good run, so they catch silent future drift in the key-gen
    arithmetic (C1, ROL-87, the add) — but they are NOT an independent oracle.
    The generator's *absolute* correctness is proven at the retail layer in
    Session B, where the NCCH protected-hash gate (an independent, on-disk
    declaration) is the oracle.
    """
    keyx = bytes.fromhex("00112233445566778899aabbccddeeff")
    keyy = bytes.fromhex("ffeeddccbbaa99887766554433221100")
    normalkey = normalkey_from_keyxy(keyx, keyy)
    counter = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = b"New3DS 9.6 NCCH decryption test payload!!"  # 40 bytes
    ciphertext = aes128_ctr_xor(normalkey, counter, plaintext)
    # Round-trip first — always must hold.
    assert aes128_ctr_xor(normalkey, counter, ciphertext) == plaintext
    # Pin the derived normalkey + ciphertext against silent drift.
    assert normalkey.hex() == "c3aed410c30fd21f56387e822f2ba348"
    assert ciphertext.hex() == (
        "edf7c109c1c7245c27296f7af03cb28f"
        "b4d0d10eae840d0df21d6e1f78d26453"
        "881038b23d2cc50d60"
    )
