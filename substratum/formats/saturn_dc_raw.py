"""Saturn / Dreamcast raw disc image normalizer (NORMALIZERS.md row
`saturn/dc-raw`).

Remaps a raw 2352-byte-sector CD-ROM Mode 1 disc image (a Saturn CD or a
Dreamcast GD-ROM data track) to the 2048-byte user-data stream the
existing `iso9660` normalizer walks. Returns exactly ONE layer — a
`ByteView`; the caller re-normalizes it with `iso9660` (DESIGN §1
composition rule; same shape as `chd` and `ps1_bincue`).

Sector layout (ECMA-130 / Yellow Book Mode 1):
  [0:12)      sync     (`00 FF*10 00`)
  [12:16)     header   (BCD minute/second/frame + mode=1)
  [16:2064)   user data (2048 bytes)
  [2064:2068) EDC      (CD-ROM EDC over [0, 2064))
  [2068:2076) reserved (8 zero bytes)
  [2076:2352) ECC      (276 bytes)
  total = 12+4+2048+4+8+276 = 2352 bytes

This is the Mode 1 sibling of `ps1_bincue` (which handles Mode 2 XA).
Saturn and DC both store 2048-byte user data inside 2352-byte raw
Mode 1 sectors; the difference is the absence of the 8-byte XA subheader
and the mode byte (1 vs 2). The whole file is one contiguous data track —
no .cue is required (the registry lists `deps: none` and the differential
is `7z` on the inner ISO).

Scope — deliberately unit-bounded (mirrors `ps1_bincue` discipline):
- 2352-byte CD-ROM Mode 1 raw, single data track, no cue.
- 2048-byte raw images are `iso9660`'s domain (redundant unit) — they
  sniff False here and fall through to `iso9660`.
- Refused structurally: multi-track/audio, mode != 1, bad sync, invalid
  BCD/MSF address, non-contiguous sector addresses, size not a multiple
  of 2352.

Runtime is stdlib-only per DESIGN.md § 4.
"""

from __future__ import annotations

from substratum.contract import ByteSource, ByteView, FileSource

__all__ = ["sniff", "normalize_saturn_dc_raw", "lba_base"]

# --- CD-ROM Mode 1 sector layout (ECMA-130 / Yellow Book) ------------------
SECTOR = 2352
SYNC_LEN = 12
HEADER_LEN = 4
USER_LEN = 2048
EDC_LEN = 4
RESERVED_LEN = 8  # Mode 1 has an 8-byte reserved gap between EDC and ECC
ECC_LEN = 276
_RAW_BATCH_SECTORS = 512  # 1,204,224 raw bytes; bounded near the 1 MiB gate chunk
assert SYNC_LEN + HEADER_LEN + USER_LEN + EDC_LEN + RESERVED_LEN + ECC_LEN == SECTOR
# user data lives at [16:2064)
USER_START = SYNC_LEN + HEADER_LEN  # 16
USER_END = USER_START + USER_LEN  # 2064

SYNC = b"\x00" + b"\xFF" * 10 + b"\x00"  # 12 bytes
MODE1 = 0x01
MSF_OFFSET = SYNC_LEN  # header[0:3] -> absolute [12:15)
MSF_LEN = 3
# mode byte is the 4th byte of the 4-byte header -> absolute offset 15
MODE_OFFSET = SYNC_LEN + HEADER_LEN - 1  # 15


def _from_bcd(value: int, field: str, index: int) -> int:
    high, low = value >> 4, value & 0x0F
    if high > 9 or low > 9:
        raise ValueError(
            f"saturn-dc-raw: sector {index} invalid BCD {field} 0x{value:02x}"
        )
    return high * 10 + low


def _decode_minute(value: int, index: int) -> int:
    """Decode a sector-address minute byte.

    Standard BCD for minutes 0-99. The GD-ROM high-density area continues
    the pattern past 99:59:74 with hexadecimal tens digits — minute 100 is
    0xA0, up to 0xC2 (=122) at a full 1.2 GB track's end (characterized on
    a real dump: Sonic Adventure 2 track03, 2026-08-14). Genuine Saturn
    media tops out at 99:59:74, so the relaxed high nibble never fires
    there, and the per-sector MSF contiguity check remains the structural
    gate against a planted continuation byte at a wrong position.
    """
    high, low = value >> 4, value & 0x0F
    if low > 9:
        raise ValueError(
            f"saturn-dc-raw: sector {index} invalid BCD minute 0x{value:02x}"
        )
    return high * 10 + low


def _decode_msf(raw: bytes, index: int) -> int:
    minute = _decode_minute(raw[MSF_OFFSET], index)
    second = _from_bcd(raw[MSF_OFFSET + 1], "second", index)
    frame = _from_bcd(raw[MSF_OFFSET + 2], "frame", index)
    if second >= 60:
        raise ValueError(
            f"saturn-dc-raw: sector {index} MSF second {second} >= 60"
        )
    if frame >= 75:
        raise ValueError(
            f"saturn-dc-raw: sector {index} MSF frame {frame} >= 75"
        )
    return (minute * 60 + second) * 75 + frame


def _format_msf(frame_number: int) -> str:
    minute, remainder = divmod(frame_number, 60 * 75)
    second, frame = divmod(remainder, 75)
    return f"{minute:02d}:{second:02d}:{frame:02d}"


def _validate_sector_structure(raw: bytes, index: int) -> int:
    """Validate one sector's fixed fields and return its absolute MSF frame."""
    if len(raw) != SECTOR:
        raise ValueError(
            f"saturn-dc-raw: sector {index} short read ({len(raw)} < {SECTOR})"
        )
    if raw[:SYNC_LEN] != SYNC:
        raise ValueError(
            f"saturn-dc-raw: sector {index} bad sync pattern "
            f"(got {raw[:SYNC_LEN].hex()})"
        )
    if raw[MODE_OFFSET] != MODE1:
        raise ValueError(
            f"saturn-dc-raw: sector {index} mode {raw[MODE_OFFSET]} != 1 "
            "(Mode 2 / audio are out of scope)"
        )
    return _decode_msf(raw, index)


def _validate_mode1_sector(raw: bytes, index: int, origin_msf: int) -> bytes:
    """Validate one raw Mode-1 sector and return its 2048-byte user block."""
    got_msf = _validate_sector_structure(raw, index)
    expected_msf = origin_msf + index
    if got_msf != expected_msf:
        raise ValueError(
            f"saturn-dc-raw: sector {index} MSF {_format_msf(got_msf)} "
            f"is not contiguous (expected {_format_msf(expected_msf)})"
        )
    return raw[USER_START:USER_END]


class _Mode1RemapSource:
    """Lazy ByteSource over the Mode 1 user-data stream.

    Nothing is materialized (DESIGN §1): `read_at` maps output offsets
    to (sector index, sector offset) and reads each 2352-byte sector
    from the underlying raw image on demand, returning only the 2048-byte
    user block [16:2064]. A one-sector cache keeps sequential reads
    within a sector from re-reading the raw bytes.
    """

    def __init__(self, raw: ByteSource, n_sectors: int, origin_msf: int) -> None:
        self._raw = raw
        self._n = n_sectors
        self._origin_msf = origin_msf
        self._cache_i = -1
        self._cache_user = b""

    def size(self) -> int:
        return self._n * USER_LEN

    def _sector_user(self, i: int) -> bytes:
        """Read sector i's 2048-byte user block, validating sync + mode 1."""
        if i == self._cache_i:
            return self._cache_user
        raw = self._raw.read_at(i * SECTOR, SECTOR)
        user = _validate_mode1_sector(raw, i, self._origin_msf)
        self._cache_i = i
        self._cache_user = user
        return user

    def read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self.size():
            raise ValueError(
                f"read [{offset}, {offset + size}) out of bounds (size {self.size()})"
            )
        out = bytearray()
        pos, stop = offset, offset + size
        while pos < stop:
            first_sector = pos // USER_LEN
            within = pos % USER_LEN
            sectors_needed = (within + stop - pos + USER_LEN - 1) // USER_LEN
            batch_count = min(_RAW_BATCH_SECTORS, sectors_needed)
            raw_batch = self._raw.read_at(
                first_sector * SECTOR, batch_count * SECTOR
            )
            for batch_index in range(batch_count):
                sector_index = first_sector + batch_index
                raw_offset = batch_index * SECTOR
                raw = raw_batch[raw_offset : raw_offset + SECTOR]
                block = _validate_mode1_sector(
                    raw, sector_index, self._origin_msf
                )
                self._cache_i = sector_index
                self._cache_user = block
                block_offset = within if batch_index == 0 else 0
                take = min(USER_LEN - block_offset, stop - pos)
                out += block[block_offset : block_offset + take]
                pos += take
                if pos == stop:
                    break
        return bytes(out)


def sniff(source: ByteSource) -> bool:
    """True when the source begins with the CD-ROM Mode 1 sync pattern AND
    carries mode byte 1 at offset 15.

    A 2048-byte raw ISO has no sync at [0:12] (and no mode byte), so it
    sniffs False here and falls through to `iso9660`. A ps1-bincue Mode 2
    raw sniffs True on sync but carries mode byte 2 -> False here. Bounded
    — refuse look-alikes, don't guess."""
    if source.size() < SECTOR:
        return False
    if source.read_at(0, SYNC_LEN) != SYNC:
        return False
    return source.read_at(MODE_OFFSET, 1) == b"\x01"


def lba_base(source) -> int:
    """Disc-absolute LBA where this raw data track begins.

    Derived from sector 0's own address header (ECMA-130: LBA 0 = MSF
    00:02:00, i.e. the 150-frame pregap). A Saturn CD track starts at or
    near LBA 0 → ``0``; a Dreamcast GD-ROM high-density track starts at
    absolute MSF 10:02:00 → ``45_000``. GD data tracks are mastered with
    ISO9660 extent locations **absolute from disc start** (verified on a
    staged SA2 dump: every extent — PVD root record, path tables,
    directory records — carries exactly +45,000), so the documented GD
    composition is::

        view = normalize(track, format="saturn-dc-raw")
        tree = normalize_iso9660(view.source, lba_base=lba_base(track))
    """
    src = source if isinstance(source, ByteSource) else FileSource(source)
    header = src.read_at(MSF_OFFSET, 3)
    frames = (
        _decode_minute(header[0], 0) * 60 * 75
        + _from_bcd(header[1], "second", 0) * 75
        + _from_bcd(header[2], "frame", 0)
    )
    if frames < 150:
        raise ValueError(
            f"saturn-dc-raw: track starts at MSF frame {frames} (< 00:02:00); "
            "not an ECMA-130 data track"
        )
    return frames - 150


def normalize_saturn_dc_raw(source) -> ByteView:
    """Map a 2352-byte raw Mode 1 disc image to a ByteView of the inner
    2048-byte ISO9660 stream.

    Accepts a path (str/Path) or a `ByteSource`. Returns a lazy
    `ByteView` — the caller composes with `iso9660` (DESIGN §1).

    Refusals (structural reds): empty, size not a multiple of 2352,
    any-sector sync mismatch, any-sector mode != 1, invalid BCD/MSF, or
    non-contiguous sector addresses.
    """
    src = source if isinstance(source, ByteSource) else FileSource(source)
    if src.size() == 0:
        raise ValueError("saturn-dc-raw: empty image")
    if src.size() % SECTOR != 0:
        raise ValueError(
            f"saturn-dc-raw: size {src.size()} not a multiple of {SECTOR} "
            "(not a raw disc image)"
        )
    n_sectors = src.size() // SECTOR

    # Eager structural pass: validate sync + mode + BCD/MSF sequence on
    # every sector at normalize time, so corruption surfaces as a check-1
    # structural red rather than a check-4 fidelity error mid-read.
    # Bounded raw batches are read and immediately discarded; the user
    # stream is NOT materialized.
    origin_msf: int | None = None
    for batch_start in range(0, n_sectors, _RAW_BATCH_SECTORS):
        batch_count = min(_RAW_BATCH_SECTORS, n_sectors - batch_start)
        raw_batch = src.read_at(
            batch_start * SECTOR, batch_count * SECTOR
        )
        for batch_index in range(batch_count):
            i = batch_start + batch_index
            raw_offset = batch_index * SECTOR
            raw = raw_batch[raw_offset : raw_offset + SECTOR]
            if origin_msf is None:
                origin_msf = _validate_sector_structure(raw, i)
            else:
                _validate_mode1_sector(raw, i, origin_msf)

    assert origin_msf is not None
    return ByteView(
        source=_Mode1RemapSource(src, n_sectors, origin_msf),
        format="saturn-dc-raw",
    )
