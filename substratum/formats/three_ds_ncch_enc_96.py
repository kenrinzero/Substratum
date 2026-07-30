"""Nintendo 3DS New3DS 9.6 encrypted-NCCH decode normalizer (pure-Python AES-CTR).

Decrypts one New3DS-9.6-encrypted NCCH (``ncchflag[3] == 0x0B``, keyslot
``0x1B``) into a decrypted ``ByteView`` whose bytes are a NoCrypto NCCH image —
the same shape ``three_ds_ncch`` consumes. The caller composes
``normalize(view.source, format="3ds-ncch")`` to walk the regions, exactly as
``3ds-ncch-enc`` does for standard crypto (DESIGN.md section 1).

**Why a separate module, not a widening of ``three_ds_ncch-enc``:** vendored
ctrtool v1.3.0 cannot decrypt keyslot ``0x1B`` (docs/3DS-KEYED-WORK.md
"CORRECTION (2026-07-30)"), so this layer bypasses ctrtool entirely and decrypts
in pure Python. It reads the ``0x2C`` and ``0x1B`` keyX values directly from the
operator-supplied keyset, derives the AES normal keys via the hardware key
generator (``substratum/_aes.py``), and CTR-decrypts the regions on demand. That
is a meaningfully different dispatch shape from the ctrtool-subprocess modules.

**Load-bearing: the two-key NCCH decryption model (verified against FE Warriors
retail bytes, 2026-07-30).** A New3DS-9.6 NCCH does NOT decrypt all of its
encrypted regions with one key. There are two AES normal keys — both derived
from the same keyY (NCCH signature[:16]) but different keyX slots:

- **Key0** (``slot0x2C``, the original content keyslot): encrypts the extended
  header, the ExeFS *superblock* (the 0x200 header), and the ExeFS bytes after
  the first file.
- **Key1** (``slot0x1B`` for 9.6 / ``slot0x18`` for 9.3, the "new" keyslot):
  encrypts the first ExeFS file's content (``.code``) and the *entire* RomFS.

The ExeFS region is therefore decrypted as ONE continuous CTR stream whose key
switches mid-stream: Key0 over [0, 0x200), Key1 over [0x200, 0x200+code_size),
Key0 over the remainder. The counter never resets between these sub-spans
(3dstool ``src/ncch.cpp`` extract: the counter is set once per region and the
byte offset advances the keystream). This is why a naive "one key per region"
decrypt fails the protected-hash gate — confirmed empirically before this
normalizer shipped.

**No-seed 9.6 scope (this unit):** the New3DS 9.6 variant has two sub-variants
selected by ``ncchflag[7] & 0x20`` (the keyY-seed bit). Clear → no-seed 9.6
(keyY = signature[:16]); this unit. Set → seeded 9.6 (the seeddb modifies keyY);
deferred (mirrors the standard/seed split of the 7.x family). New3DS 9.3
(``0x0A``, ``0x18``) is architecturally identical and supported by the same path
once a ``0x18`` anchor exists (genuine 9.3 titles are effectively lost media).

The NCCH header at 0x100 is **plaintext** for no-seed 9.6 (only the 7.x-seed
variant encrypts the header), so this layer consumes a raw NCCH slice (e.g. a
partition cut from a CCI via ``3ds-cci``), not a whole CIA.

The independent correctness anchor is the NCCH-declared protected SHA-256
hashes, validated when the decrypted ``ByteView`` composes through
``three_ds_ncch`` — a wrong key, counter, keyY, or key-per-region mapping fails
them (3dstool cannot second-party 9.6: no ``--seeddb`` and it lacks the working
``0x1B`` decrypt path here).

Runtime is stdlib-only per DESIGN.md section 4. See
docs/3DS-PURE-PYTHON-AES-CTR-PLAN.md for the full algorithm and provenance.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

from substratum._aes import aes128_ctr_xor, normalkey_from_keyxy
from substratum.contract import ByteSource, ByteView, FileSource

__all__ = ["sniff", "normalize_3ds_ncch_enc_96"]

_HEADER_SIZE = 0x200
_MAGIC_OFFSET = 0x100
_NCCH_MAGIC = b"NCCH"

# NCCH header field offsets (little-endian), duplicated from three_ds_ncch so
# this decode layer is independently dispatchable.
_FORMAT_VERSION_OFFSET = 0x112
_CONTENT_SIZE_UNITS_OFFSET = 0x104
_BLOCK_SIZE_LOG_OFFSET = 0x18E
_OTHER_FLAGS_OFFSET = 0x18F
_NCCH_FLAGS_OFFSET = 0x188
_NO_ENCRYPTION = 1 << 2
_SEEDED_AES_KEY_Y = 1 << 5

_EXHEADER_SIZE_OFFSET = 0x180
_PLAIN_FIELD = 0x190
_LOGO_FIELD = 0x198
_EXEFS_FIELD = 0x1A0
_EXEFS_HASHSIZE_OFFSET = 0x1A8  # protected-Units field
_ROMFS_FIELD = 0x1B0
_ROMFS_HASHSIZE_OFFSET = 0x1B8  # protected-Units field
_EXHEADER_REGION_OFFSET = _HEADER_SIZE  # 0x200
_ACCESS_DESCRIPTOR_SIZE = 0x400

# AES + counter geometry.
_AES_BLOCK = 16
_TITLE_ID_OFFSET = 0x108
_TITLE_ID_SIZE = 8
_EXEFS_SUPERBLOCK_SIZE = 0x200  # the 10-entry ExeFS header (the protected region)

# Region magic byte (counter[8]) for the version-2 NCCH AES counter, confirmed
# in ctrKeyGen.py:130-147 (getNcchAesCounter) and ctrtool -v: 1=exheader,
# 2=exefs, 3=romfs. ExeFS sub-spans share the exefs counter (continuous stream).
_MAGIC_EXHEADER = 1
_MAGIC_EXEFS = 2
_MAGIC_ROMFS = 3

# Keyset discipline (mirrors the Wii common-key boundary,
# docs/WII-KEYED-WORK.md): the operator's aes_keys.txt is named by an env var;
# code reads only the requested slot0x..KeyX lines, reports presence-only, and
# never hashes/logs/echoes a key byte.
_KEYSET_ENV = "SUBSTRATUM_3DS_KEYSET_FILE"

# ncchflag[3] -> (new-keyslot name in the keyset, human label). 0x0A (9.3) and
# 0x0B (9.6) share the code path. The OLD keyslot is always 0x2C for both.
_NEW_KEYSLOTS = {
    0x0A: ("slot0x18KeyX", "New3DS 9.3 (0x18)"),
    0x0B: ("slot0x1BKeyX", "New3DS 9.6 (0x1B)"),
}
_OLD_KEYSLOT_NAME = "slot0x2CKeyX"


def _load_keyx(slot_name: str) -> bytes:
    """Load one keyX from the operator-supplied keyset, presence-only.

    The keyset is an ``aes_keys.txt`` (the canonical ctrtool/3dstool format):
    ``slot0xNNKeyX=<32 hex>`` lines. Only the requested line is read; its value
    is never hashed, logged, or echoed. Fails closed when the env var is unset,
    the file is missing, or the slot is absent/malformed.
    """
    raw = os.environ.get(_KEYSET_ENV)
    if not raw:
        raise ValueError(
            f"{_KEYSET_ENV} is not set; supply the 3DS keyset path "
            "(see docs/3DS-KEYED-WORK.md)"
        )
    path = Path(raw)
    if not path.is_file():
        raise ValueError(
            f"{_KEYSET_ENV} points to a missing file "
            "(see docs/3DS-KEYED-WORK.md)"
        )
    needle = f"{slot_name}="
    with path.open("r", encoding="ascii", errors="replace") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped.startswith(needle):
                hexval = stripped[len(needle):].strip()
                try:
                    keyx = bytes.fromhex(hexval)
                except ValueError as exc:  # malformed hex
                    raise ValueError(
                        f"{slot_name} in the keyset is not valid hex "
                        "(see docs/3DS-KEYED-WORK.md)"
                    ) from exc
                if len(keyx) != _AES_BLOCK:
                    raise ValueError(
                        f"{slot_name} in the keyset is not 16 bytes "
                        "(see docs/3DS-KEYED-WORK.md)"
                    )
                return keyx
    raise ValueError(
        f"{slot_name} not found in the keyset "
        "(see docs/3DS-KEYED-WORK.md)"
    )


def sniff(source: ByteSource) -> bool:
    """True for a New3DS-9.6/9.3 encrypted NCCH (no-seed sub-variant).

    The NCCH magic at 0x100 is plaintext for no-seed 9.6/9.3 (the header is not
    encrypted), so this sniffer — registered *before* ``3ds-ncch-enc`` and
    ``3ds-ncch`` — claims the ``0x0A``/``0x0B`` crypto methods with the seed bit
    clear and NoCrypto clear. The seeded-9.6 sub-variant (seed bit set) is left
    for a future widening; standard/7.x go to ``3ds-ncch-enc``.
    """
    if source.size() < _MAGIC_OFFSET + 4:
        return False
    if source.read_at(_MAGIC_OFFSET, 4) != _NCCH_MAGIC:
        return False
    other_flags = source.read_at(_OTHER_FLAGS_OFFSET, 1)
    if other_flags[0] & _NO_ENCRYPTION:
        return False  # already decrypted -> 3ds-ncch's domain
    if other_flags[0] & _SEEDED_AES_KEY_Y:
        return False  # seeded 9.6 sub-variant -> future widening
    crypto = source.read_at(_NCCH_FLAGS_OFFSET + 3, 1)
    return crypto[0] in _NEW_KEYSLOTS


def _region_fields(header: bytes, field_offset: int, block_size: int):
    """Return (byte_offset, byte_size) for a region table entry, or None when
    the region is absent."""
    offset_units, size_units = struct.unpack_from("<II", header, field_offset)
    if offset_units == 0 and size_units == 0:
        return None
    if offset_units == 0 or size_units == 0:
        raise ValueError(
            f"half-empty region at field 0x{field_offset:x}: "
            f"offset={offset_units}, size={size_units}"
        )
    return offset_units * block_size, size_units * block_size


def _protected_units(header: bytes, hashsize_offset: int) -> int:
    """The protected-Units field that follows a region's offset/size pair."""
    return struct.unpack_from("<I", header, hashsize_offset)[0]


def _build_encrypted_spans(
    header: bytes,
    src: ByteSource,
    block_size: int,
    keys: tuple[bytes, bytes],
    title_id: bytes,
) -> list[tuple[int, int, int, int]]:
    """Build the sorted, non-overlapping list of encrypted sub-spans as
    ``(offset, size, key_index, magic)`` tuples.

    Per the two-key model (module docstring): exheader + ExeFS-superblock +
    ExeFS-tail use Key0; the first ExeFS file (``.code``) + RomFS use Key1. The
    ExeFS sub-spans share one continuous CTR stream (the exefs magic), so their
    counters are region-relative block indices — the lazy decryptor computes the
    counter from the span's region magic + the block index within that region.
    """
    key0, key1 = keys
    spans: list[tuple[int, int, int, int]] = []

    exheader_size = struct.unpack_from("<I", header, _EXHEADER_SIZE_OFFSET)[0]
    if exheader_size:
        if exheader_size != 0x400:
            raise ValueError(f"invalid extended-header size {exheader_size:#x}")
        # exheader region = exheader + access descriptor; Key0 (old slot).
        spans.append(
            (
                _EXHEADER_REGION_OFFSET,
                exheader_size + _ACCESS_DESCRIPTOR_SIZE,
                0,  # key index 0
                _MAGIC_EXHEADER,
            )
        )

    exefs = _region_fields(header, _EXEFS_FIELD, block_size)
    if exefs is not None:
        exefs_off, exefs_size = exefs
        # The first ExeFS file's size is needed to split the ExeFS stream. It
        # lives in the ExeFS superblock (file 0's size field at superblock+0x0C),
        # which is plaintext AFTER decrypting the 0x200 superblock with Key0.
        sb_enc = src.read_at(exefs_off, _EXEFS_SUPERBLOCK_SIZE)
        exefs_counter0 = _initial_counter(title_id, _MAGIC_EXEFS)
        sb = aes128_ctr_xor(key0, exefs_counter0, sb_enc)
        # ExeFS file header: name[8] + offset u32 + size u32; file 0 at +0.
        code_offset = struct.unpack_from("<I", sb, 0x08)[0]
        code_size = struct.unpack_from("<I", sb, 0x0C)[0]
        # file0.offset is relative to the ExeFS content (after superblock) and is
        # normally 0; the code bytes start at exefs_off + _EXEFS_SUPERBLOCK_SIZE.
        code_region_off = exefs_off + _EXEFS_SUPERBLOCK_SIZE + code_offset
        code_region_end = min(code_region_off + code_size, exefs_off + exefs_size)
        if code_region_end <= code_region_off:
            # No .code content; the whole ExeFS is Key0.
            spans.append((exefs_off, exefs_size, 0, _MAGIC_EXEFS))
        else:
            # Key0 superblock span.
            spans.append((exefs_off, _EXEFS_SUPERBLOCK_SIZE, 0, _MAGIC_EXEFS))
            # Key1 .code span.
            spans.append(
                (
                    code_region_off,
                    code_region_end - code_region_off,
                    1,  # key index 1
                    _MAGIC_EXEFS,
                )
            )
            # Key0 tail span (rest of ExeFS).
            tail_off = code_region_end
            if tail_off < exefs_off + exefs_size:
                spans.append(
                    (
                        tail_off,
                        exefs_off + exefs_size - tail_off,
                        0,
                        _MAGIC_EXEFS,
                    )
                )

    romfs = _region_fields(header, _ROMFS_FIELD, block_size)
    if romfs is not None:
        # Entire RomFS uses Key1 (new slot).
        spans.append((romfs[0], romfs[1], 1, _MAGIC_ROMFS))

    spans.sort(key=lambda s: s[0])
    return spans


def _initial_counter(title_id: bytes, magic: int) -> bytes:
    """The version-2 NCCH AES counter block 0 for a region: titleId reversed
    (big-endian) + 1-byte region magic + 7 zero bytes (ctrKeyGen.py:130-147)."""
    counter = bytearray(16)
    counter[0:8] = title_id[::-1]
    counter[8] = magic
    return bytes(counter)


class _DecryptedNcchSource:
    """A lazy ``ByteSource`` over a decrypted NoCrypto NCCH image.

    The full NCCH image is never materialized (the romfs alone can be ~2 GB at
    ~0.5 MiB/s of pure-Python AES). Plaintext regions (header, plain, logo,
    access descriptor when not in the exheader span) pass straight through from
    the parent; the encrypted sub-spans (exheader, ExeFS superblock/.code/tail,
    RomFS) are AES-CTR decrypted on demand, windowed to the requested byte range
    with a bounded block-aligned cache.

    The presented header has the NoCrypto bit set so the caller-composed
    ``three_ds_ncch`` accepts the image (it refuses encrypted content).
    """

    def __init__(
        self,
        parent: ByteSource,
        keys: tuple[bytes, bytes],
        title_id: bytes,
        spans: tuple[tuple[int, int, int, int], ...],
        region_base: dict[int, int],
    ) -> None:
        # spans: (offset, size, key_index, magic). region_base: maps a span
        # offset to its region's base offset (for counter block indexing when
        # spans are sub-regions of one continuous CTR stream, e.g. ExeFS).
        self._parent = parent
        self._keys = keys
        self._title_id = title_id
        self._spans = spans
        self._region_base = region_base
        self._size = parent.size()
        self._cache: dict[tuple[int, int], bytes] = {}
        self._cache_order: list[tuple[int, int]] = []
        self._cache_cap = 4

    def _span_at(self, abs_off: int):
        for span in self._spans:
            off, size, key_idx, magic = span
            if off <= abs_off < off + size:
                return span
        return None

    def _counter(self, magic: int, block_index: int) -> bytes:
        counter = bytearray(16)
        counter[0:8] = self._title_id[::-1]
        counter[8] = magic
        c = int.from_bytes(counter, "big") + block_index
        return (c & ((1 << 128) - 1)).to_bytes(16, "big")

    def _decrypt_window(
        self, region_base: int, magic: int, key: bytes, start_block: int, n_blocks: int
    ) -> bytes:
        cache_key = (region_base, start_block)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached
        block_byte_off = region_base + start_block * _AES_BLOCK
        ciphertext = self._parent.read_at(block_byte_off, n_blocks * _AES_BLOCK)
        counter = self._counter(magic, start_block)
        plaintext = aes128_ctr_xor(key, counter, ciphertext)
        self._cache[cache_key] = plaintext
        self._cache_order.append(cache_key)
        if len(self._cache_order) > self._cache_cap:
            evict = self._cache_order.pop(0)
            self._cache.pop(evict, None)
        return plaintext

    def read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self._size:
            raise ValueError(
                f"read [{offset}, {offset + size}) out of bounds "
                f"(decrypted size {self._size})"
            )
        if size == 0:
            return b""
        out = bytearray()
        pos = offset
        end = offset + size
        while pos < end:
            span = self._span_at(pos)
            if span is None:
                # Plaintext span: read up to the next encrypted span (or end).
                next_enc = end
                for s_off, _s_size, _k, _m in self._spans:
                    if pos < s_off < next_enc:
                        next_enc = s_off
                take = min(next_enc - pos, end - pos)
                chunk = self._parent.read_at(pos, take)
                out += self._override_header_nocrypto(pos, chunk)
                pos += take
            else:
                s_off, s_size, key_idx, magic = span
                region_base = self._region_base[s_off]
                key = self._keys[key_idx]
                span_end = min(end, s_off + s_size)
                while pos < span_end:
                    # Block index is relative to the CTR stream's region base
                    # (exefs sub-spans share one stream).
                    blk = (pos - region_base) // _AES_BLOCK
                    win_blocks = min(256, (span_end - region_base + _AES_BLOCK - 1) // _AES_BLOCK - blk)
                    if win_blocks <= 0:
                        win_blocks = 1
                    window = self._decrypt_window(
                        region_base, magic, key, blk, win_blocks
                    )
                    win_off = pos - (region_base + blk * _AES_BLOCK)
                    take = min(win_blocks * _AES_BLOCK - win_off, span_end - pos)
                    out += window[win_off : win_off + take]
                    pos += take
        return bytes(out)

    def _override_header_nocrypto(self, pos: int, chunk: bytes) -> bytes:
        """If this plaintext read covers the NoCrypto flag byte (0x18F), set it."""
        flag = _OTHER_FLAGS_OFFSET
        if pos <= flag < pos + len(chunk):
            out = bytearray(chunk)
            local = flag - pos
            out[local] = out[local] | _NO_ENCRYPTION
            return bytes(out)
        return chunk

    def size(self) -> int:
        return self._size

    def close(self) -> None:
        self._cache.clear()
        self._cache_order.clear()


def _validate_header(header: bytes, source_size: int) -> tuple[int, int]:
    """Validate the NCCH header + the no-seed 9.6/9.3 scope; return
    (block_size, ncchflag[3])."""
    if header[_MAGIC_OFFSET : _MAGIC_OFFSET + 4] != _NCCH_MAGIC:
        raise ValueError("not a 3DS NCCH image (missing NCCH magic)")

    format_version = struct.unpack_from("<H", header, _FORMAT_VERSION_OFFSET)[0]
    if format_version == 1:
        raise ValueError("NCCH prototype format version 1 is outside scope")
    if format_version not in {0, 2}:
        raise ValueError(f"unsupported NCCH format version {format_version}")

    block_size_log = header[_BLOCK_SIZE_LOG_OFFSET]
    if block_size_log > 31:
        raise ValueError(f"invalid NCCH block-size log {block_size_log}")
    block_size = 1 << (block_size_log + 9)

    content_units = struct.unpack_from("<I", header, _CONTENT_SIZE_UNITS_OFFSET)[0]
    declared_size = content_units * block_size
    if declared_size != source_size:
        raise ValueError(
            f"declared NCCH content size {declared_size} does not match "
            f"source size {source_size}"
        )

    crypto_method = header[_NCCH_FLAGS_OFFSET + 3]
    if crypto_method not in _NEW_KEYSLOTS:
        raise ValueError(
            f"NCCH crypto method 0x{crypto_method:02x} is outside 9.6/9.3 scope"
        )

    other_flags = header[_OTHER_FLAGS_OFFSET]
    if other_flags & _NO_ENCRYPTION:
        raise ValueError(
            "NCCH is already decrypted (NoCrypto); use the 3ds-ncch normalizer"
        )
    if other_flags & _SEEDED_AES_KEY_Y:
        raise ValueError(
            "seeded-9.6 NCCH (seed bit set) is outside this no-seed unit's scope"
        )
    return block_size, crypto_method


def normalize_3ds_ncch_enc_96(source) -> ByteView:
    """Decrypt one no-seed New3DS-9.6/9.3 NCCH into a NoCrypto ``ByteView``.

    Accepts a path (str/Path) or ``ByteSource`` over an encrypted NCCH slice (a
    partition cut from a CCI via ``3ds-cci``, or a standalone ``.ncch``). Reads
    the ``0x2C`` and ``0x1B``/``0x18`` keyX values from the operator keyset
    (``SUBSTRATUM_3DS_KEYSET_FILE``), derives the two AES normal keys (both from
    keyY = signature[:16]), and returns a lazy ``ByteView`` that CTR-decrypts
    the encrypted sub-spans on demand with the correct per-span key, with the
    NoCrypto header bit set. ``three_ds_ncch`` consumes the image directly.
    """
    src = source if isinstance(source, ByteSource) else FileSource(source)
    source_size = src.size()
    if source_size < _HEADER_SIZE:
        raise ValueError("source too small to contain a 3DS NCCH header")
    header = src.read_at(0, _HEADER_SIZE)
    block_size, crypto_method = _validate_header(header, source_size)

    # Both keyX values: the always-0x2C old slot and the 9.6/9.3 new slot.
    kx_old = _load_keyx(_OLD_KEYSLOT_NAME)
    slot_name, _label = _NEW_KEYSLOTS[crypto_method]
    kx_new = _load_keyx(slot_name)
    keyy = header[0:16]  # NCCH signature's first 16 bytes
    key0 = normalkey_from_keyxy(kx_old, keyy)
    key1 = normalkey_from_keyxy(kx_new, keyy)

    title_id = src.read_at(_TITLE_ID_OFFSET, _TITLE_ID_SIZE)

    spans_raw = _build_encrypted_spans(
        header, src, block_size, (key0, key1), title_id
    )

    # Map each span offset to its CTR-stream region base: exheader/romfs spans
    # are their own region base; exefs sub-spans all share the exefs region base
    # (one continuous counter stream across the superblock/.code/tail split).
    region_base: dict[int, int] = {}
    exefs_off_units, _ = struct.unpack_from("<II", header, _EXEFS_FIELD)
    exefs_base = exefs_off_units * block_size
    for off, _size, _key_idx, magic in spans_raw:
        if magic == _MAGIC_EXEFS:
            region_base[off] = exefs_base
        else:
            region_base[off] = off

    # Defensive: spans must be in-bounds, non-overlapping, and contiguous-within-
    # region (an exefs split must not leave a gap inside the exefs region).
    prev_end = _HEADER_SIZE
    for off, size, _k, _m in spans_raw:
        if off < prev_end:
            raise ValueError(
                f"encrypted span at {off:#x} overlaps the previous span"
            )
        if off + size > source_size:
            raise ValueError(
                f"encrypted span [{off:#x}, {off + size:#x}) exceeds source "
                f"size {source_size:#x}"
            )
        prev_end = off + size

    decoded = _DecryptedNcchSource(
        src,
        (key0, key1),
        title_id,
        tuple(spans_raw),
        region_base,
    )
    return ByteView(source=decoded, format="3ds-ncch-enc-96")
