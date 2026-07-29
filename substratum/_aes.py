"""Pure-Python AES-128 decryption in CBC mode (FIPS-197 / SP 800-38A).

Substratum's runtime is stdlib-only by DESIGN.md §4, and the Python stdlib
ships no symmetric cipher. The Wii partition layer needs AES-128-CBC *decryption*
only (disc data is read-only), so this module implements exactly that: single-
block AES-128 decrypt, wrapped by CBC chaining. Encryption exists only as the
synthetic-fixture authoring path under seedtools, so a generated test key can
produce a real encrypted partition that this runtime then decrypts.

Correctness is anchored independently of any Wii fixture by the NIST SP 800-38A
Appendix F.2.1 AES-128-CBC vectors (see tests/test_wii_partition.py). The
implementation is the textbook FIPS-197 construction; no clever tricks.

References:
  - FIPS-197, Advanced Encryption Standard (AES), NIST 2001.
  - SP 800-38A, Recommendation for Block Cipher Modes of Operation, NIST 2001
    (Addendum: Example Vectors), Appendix F.2.1 (CBC-AES128).
"""

from __future__ import annotations

__all__ = ["aes128_cbc_decrypt", "aes128_cbc_encrypt"]

_BLOCK = 16

# FIPS-197 §5.1.1: S-box (forward) and §5.3.2: inverse S-box.
_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)
_INV_SBOX = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

# FIPS-197 §5.2: round constants for the key schedule (Nk=4 → 10 rounds).
_RCON = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
)


def _xtime(a: int) -> int:
    """FIPS-197 §4.2.1: multiply by x in GF(2^8) under the AES polynomial."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mix_columns(state: list[int], inverse: bool) -> list[int]:
    """FIPS-197 §5.1.3 / §5.3.3: MixColumns (forward) / InvMixColumns.

    Uses the precomputed GF(2^8) product tables — the standard AES
    optimization (per-byte multiply → table lookup).
    """
    out = [0] * 16
    for c in range(4):
        i = c * 4
        s0, s1, s2, s3 = state[i], state[i + 1], state[i + 2], state[i + 3]
        if not inverse:
            out[i] = _MUL2[s0] ^ _MUL3[s1] ^ s2 ^ s3
            out[i + 1] = s0 ^ _MUL2[s1] ^ _MUL3[s2] ^ s3
            out[i + 2] = s0 ^ s1 ^ _MUL2[s2] ^ _MUL3[s3]
            out[i + 3] = _MUL3[s0] ^ s1 ^ s2 ^ _MUL2[s3]
        else:
            out[i] = _MUL14[s0] ^ _MUL11[s1] ^ _MUL13[s2] ^ _MUL9[s3]
            out[i + 1] = _MUL9[s0] ^ _MUL14[s1] ^ _MUL11[s2] ^ _MUL13[s3]
            out[i + 2] = _MUL13[s0] ^ _MUL9[s1] ^ _MUL14[s2] ^ _MUL11[s3]
            out[i + 3] = _MUL11[s0] ^ _MUL13[s1] ^ _MUL9[s2] ^ _MUL14[s3]
    return out


# Precomputed GF(2^8) multiply tables for the four AES constants that appear in
# MixColumns/InvMixColumns (2,3 forward; 9,11,13,14 inverse). Building these
# once at import replaces per-byte Russian-peasant multiplies with a lookup —
# the standard AES implementation optimization (FIPS-197 §5.1.3 notes that the
# matrix coefficients are fixed, so the products are precomputable).
_MUL2 = bytes(_xtime(i) for i in range(256))
_MUL3 = bytes(_xtime(i) ^ i for i in range(256))


def _gmul_slow(a: int, b: int) -> int:
    """GF(2^8) Russian-peasant multiply under the AES polynomial (reference)."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return result


# Inverse MixColumns uses constants 9, 11, 13, 14 — one 256-entry table each.
_MUL9 = bytes(_gmul_slow(i, 9) for i in range(256))
_MUL11 = bytes(_gmul_slow(i, 11) for i in range(256))
_MUL13 = bytes(_gmul_slow(i, 13) for i in range(256))
_MUL14 = bytes(_gmul_slow(i, 14) for i in range(256))


def _expand_key(key: bytes) -> list[list[int]]:
    """FIPS-197 §5.2: AES-128 key expansion → 11 round keys (column-wise).

    Round keys are stored column-major: ``rk[c * 4 + r]`` is row r of column c.
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    cols = [list(key[c * 4 : c * 4 + 4]) for c in range(4)]
    for i in range(4, 44):            # Nk=4, Nb=4, total 44 columns
        temp = list(cols[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]            # RotWord
            temp = [_SBOX[b] for b in temp]       # SubWord
            temp[0] ^= _RCON[i // 4]              # Rcon
        cols.append([a ^ b for a, b in zip(cols[i - 4], temp)])
    # Flatten into 11 round keys of 16 bytes each (column-major per round).
    round_keys: list[list[int]] = []
    for r in range(11):
        block = []
        for c in range(4):
            block.extend(cols[r * 4 + c])
        round_keys.append(block)
    return round_keys


def _add_round_key(state: list[int], rk: list[int]) -> None:
    for i in range(16):
        state[i] ^= rk[i]


def _sub_bytes(state: list[int]) -> None:
    for i in range(16):
        state[i] = _SBOX[state[i]]


def _inv_sub_bytes(state: list[int]) -> None:
    for i in range(16):
        state[i] = _INV_SBOX[state[i]]


def _shift_rows(state: list[int]) -> None:
    # State is column-major: element index = c*4 + r.
    state[1], state[5], state[9], state[13] = (
        state[5], state[9], state[13], state[1]
    )
    state[2], state[6], state[10], state[14] = (
        state[10], state[14], state[2], state[6]
    )
    state[3], state[7], state[11], state[15] = (
        state[15], state[3], state[7], state[11]
    )


def _inv_shift_rows(state: list[int]) -> None:
    state[1], state[5], state[9], state[13] = (
        state[13], state[1], state[5], state[9]
    )
    state[2], state[6], state[10], state[14] = (
        state[10], state[14], state[2], state[6]
    )
    state[3], state[7], state[11], state[15] = (
        state[7], state[11], state[15], state[3]
    )


def _encrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    """FIPS-197 §5.1: AES-128 single-block encrypt (column-major state)."""
    state = list(block)
    _add_round_key(state, round_keys[0])
    for rnd in range(1, 10):
        _sub_bytes(state)
        _shift_rows(state)
        state = _mix_columns(state, inverse=False)
        _add_round_key(state, round_keys[rnd])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[10])
    return bytes(state)


def _decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    """FIPS-197 §5.3: AES-128 single-block decrypt (the runtime path)."""
    state = list(block)
    _add_round_key(state, round_keys[10])
    for rnd in range(9, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys[rnd])
        state = _mix_columns(state, inverse=True)
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])
    return bytes(state)


def aes128_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """SP 800-38A §6.2: AES-128-CBC decryption.

    ``ciphertext`` length must be a positive multiple of the 16-byte block
    size; the IV is 16 bytes. Returns the decrypted plaintext (same length).
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    if len(iv) != _BLOCK:
        raise ValueError("CBC IV must be 16 bytes")
    if len(ciphertext) == 0 or len(ciphertext) % _BLOCK != 0:
        raise ValueError("ciphertext length must be a positive multiple of 16")
    round_keys = _expand_key(key)
    out = bytearray(len(ciphertext))
    prev = iv
    for i in range(0, len(ciphertext), _BLOCK):
        dec = _decrypt_block(ciphertext[i : i + _BLOCK], round_keys)
        for j in range(_BLOCK):
            out[i + j] = dec[j] ^ prev[j]
        prev = ciphertext[i : i + _BLOCK]
    return bytes(out)


def aes128_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """SP 800-38A §6.2: AES-128-CBC encryption.

    Used only by seedtools to author a synthetic partition with a generated
    test key, so the runtime decrypt path has real bytes to prove against.
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    if len(iv) != _BLOCK:
        raise ValueError("CBC IV must be 16 bytes")
    if len(plaintext) == 0 or len(plaintext) % _BLOCK != 0:
        raise ValueError("plaintext length must be a positive multiple of 16")
    round_keys = _expand_key(key)
    out = bytearray(len(plaintext))
    prev = iv
    for i in range(0, len(plaintext), _BLOCK):
        chunk = bytes(a ^ b for a, b in zip(plaintext[i : i + _BLOCK], prev))
        enc = _encrypt_block(chunk, round_keys)
        out[i : i + _BLOCK] = enc
        prev = enc
    return bytes(out)
