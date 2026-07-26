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
  [2064:2068) EDC      (CRC-32 over [12, 2064))
  [2068:2076) reserved (8 zero bytes)
  [2076:2352) ECC      (276 bytes)
  total = 12+4+2048+4+8+276 = 2352 bytes

This is the Mode 1 sibling of `ps1_bincue` (which handles Mode 2 XA
XA). Saturn and DC both store 2048-byte user data inside 2352-byte raw
Mode 1 sectors; the difference is the absence of the 8-byte XA subheader
and the mode byte (1 vs 2). The whole file is one contiguous data track —
no .cue is required (the registry lists `deps: none` and the differential
is `7z` on the inner ISO).

Scope — deliberately unit-bounded (mirrors `ps1_bincue` discipline):
- 2352-byte CD-ROM Mode 1 raw, single data track, no cue.
- 2048-byte raw images are `iso9660`'s domain (redundant unit) — they
  sniff False here and fall through to `iso9660`.
- Refused structurally: multi-track/audio, mode != 1, bad sync,
  size not a multiple of 2352.

Runtime is stdlib-only per DESIGN.md § 4.
"""

from __future__ import annotations

from substratum.contract import ByteSource, ByteView, FileSource

__all__ = ["sniff", "normalize_saturn_dc_raw"]

# --- CD-ROM Mode 1 sector layout (ECMA-130 / Yellow Book) ------------------
SECTOR = 2352
SYNC_LEN = 12
HEADER_LEN = 4
USER_LEN = 2048
EDC_LEN = 4
RESERVED_LEN = 8  # Mode 1 has an 8-byte reserved gap between EDC and ECC
ECC_LEN = 276
assert SYNC_LEN + HEADER_LEN + USER_LEN + EDC_LEN + RESERVED_LEN + ECC_LEN == SECTOR
# user data lives at [16:2064)
USER_START = SYNC_LEN + HEADER_LEN  # 16
USER_END = USER_START + USER_LEN  # 2064

SYNC = b"\x00" + b"\xFF" * 10 + b"\x00"  # 12 bytes
MODE1 = 0x01
# mode byte is the 4th byte of the 4-byte header -> absolute offset 15
MODE_OFFSET = SYNC_LEN + HEADER_LEN - 1  # 15


class _Mode1RemapSource:
    """Lazy ByteSource over the Mode 1 user-data stream.

    Nothing is materialized (DESIGN §1): `read_at` maps output offsets
    to (sector index, sector offset) and reads each 2352-byte sector
    from the underlying raw image on demand, returning only the 2048-byte
    user block [16:2064]. A one-sector cache keeps sequential reads
    within a sector from re-reading the raw bytes.
    """

    def __init__(self, raw: ByteSource, n_sectors: int) -> None:
        self._raw = raw
        self._n = n_sectors
        self._cache_i = -1
        self._cache_user = b""

    def size(self) -> int:
        return self._n * USER_LEN

    def _sector_user(self, i: int) -> bytes:
        """Read sector i's 2048-byte user block, validating sync + mode 1."""
        if i == self._cache_i:
            return self._cache_user
        raw = self._raw.read_at(i * SECTOR, SECTOR)
        if len(raw) != SECTOR:
            raise ValueError(
                f"saturn-dc-raw: sector {i} short read ({len(raw)} < {SECTOR})"
            )
        if raw[:SYNC_LEN] != SYNC:
            raise ValueError(
                f"saturn-dc-raw: sector {i} bad sync pattern (got {raw[:SYNC_LEN].hex()})"
            )
        if raw[MODE_OFFSET] != MODE1:
            raise ValueError(
                f"saturn-dc-raw: sector {i} mode {raw[MODE_OFFSET]} != 1 "
                "(Mode 2 / audio are out of scope)"
            )
        user = raw[USER_START:USER_END]
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
            block = self._sector_user(pos // USER_LEN)
            within = pos % USER_LEN
            take = min(USER_LEN - within, stop - pos)
            out += block[within : within + take]
            pos += take
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


def normalize_saturn_dc_raw(source) -> ByteView:
    """Map a 2352-byte raw Mode 1 disc image to a ByteView of the inner
    2048-byte ISO9660 stream.

    Accepts a path (str/Path) or a `ByteSource`. Returns a lazy
    `ByteView` — the caller composes with `iso9660` (DESIGN §1).

    Refusals (structural reds): empty, size not a multiple of 2352,
    any-sector sync mismatch, any-sector mode != 1.
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

    # Eager structural pass: validate sync + mode on every sector at
    # normalize time, so a corrupted sector surfaces as a check-1
    # structural red rather than a check-4 fidelity error mid-read. Only
    # 16 bytes/sector are read and immediately discarded (the user
    # stream is NOT materialized).
    for i in range(n_sectors):
        raw = src.read_at(i * SECTOR, SECTOR)
        if raw[:SYNC_LEN] != SYNC:
            raise ValueError(
                f"saturn-dc-raw: sector {i} bad sync pattern (got {raw[:SYNC_LEN].hex()})"
            )
        if raw[MODE_OFFSET] != MODE1:
            raise ValueError(
                f"saturn-dc-raw: sector {i} mode {raw[MODE_OFFSET]} != 1 "
                "(Mode 2 / audio are out of scope)"
            )

    return ByteView(source=_Mode1RemapSource(src, n_sectors), format="saturn-dc-raw")
