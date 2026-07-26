"""PS1 BIN/CUE normalizer (NORMALIZERS.md row `ps1-bincue`).

Remaps a raw 2352-byte-sector CD-ROM XA Mode 2 disc image (a PS1 or
PS2-CD `.bin` paired with a `.cue` sheet) to the fixed 2048-byte cooked
stream the existing `iso9660` normalizer walks. Returns exactly ONE layer
— a `ByteView`; the caller re-normalizes it with `iso9660` (DESIGN §1
composition rule; same shape as `chd`).

Mixed XA discs also carry Mode 2 Form-2 sectors with 2324 payload bytes.
Those cannot be concatenated into the cooked stream without shifting every
later ISO LBA. The returned ByteView therefore uses a public
`Mode2XASource`: ordinary `read_at()` exposes the LBA-stable first 2048
bytes of every sector, while `read_sector()` exposes each complete Form-1
or Form-2 payload plus its XA file/channel/submode metadata. No payload
bytes are discarded from the format-specific sector API.

Sector layout (ECMA-130 / Yellow Book Mode 2 Form 1):
  [0:12)   sync  (`00 FF*10 00`)
  [12:16)  header (BCD minute/second/frame + mode=2)
  [16:24)  XA subheader (4 bytes, repeated)
  [24:2072) user data (2048 bytes)
  [2072:2076) EDC (CRC-32 over [0, 2072))
  [2076:2352) ECC (276 bytes)
  total = 12+4+8+2048+4+276 = 2352 bytes

Sector layout (Mode 2 Form 2):
  [0:24)     sync + header + repeated XA subheader (as above)
  [24:2348)  user data (2324 bytes)
  [2348:2352) EDC (4 bytes)
  total = 12+4+8+2324+4 = 2352 bytes

The unit's substance is sector-format understanding (the spec
deliberately rejects a shell-out-to-chdman variant — that would delegate
the system's responsibility to the same tool that is the structural
anchor, collapsing toward a one-party round-trip). pycdlib is the byte
differential; chdman is the structural anchor.

Scope — deliberately unit-bounded (mirrors `iso9660` discipline):
- Mode 2 Form 1 and Form 2, including mixed/interleaved XA data. This
  normalizer exposes encoded payload bytes and XA metadata; decoding
  video/ADPCM content belongs to a downstream asset decoder.
- Mode 1, audio, multi-track, CD-TEXT, and subchannel data are refused.
- Single data track, MODE2/2352, INDEX 01 00:00:00 in the .cue.
- A .bin without a .cue sibling is refused (sniff-only on raw bytes).

Runtime is stdlib-only per DESIGN.md § 4.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from substratum.contract import ByteSource, ByteView, FileSource

__all__ = [
    "XASector",
    "Mode2XASource",
    "sniff",
    "normalize_ps1_bincue",
]

# --- CD-ROM Mode 2 Form 1 sector layout (ECMA-130) -------------------------
SECTOR = 2352
SYNC_LEN = 12
HEADER_LEN = 4
XA_SUB_LEN = 8
XA_COPY_LEN = 4
USER_LEN = 2048
FORM2_USER_LEN = 2324
EDC_LEN = 4
ECC_LEN = 276
_RAW_BATCH_SECTORS = 512  # 1,204,224 raw bytes; bounded near the 1 MiB gate chunk
assert SYNC_LEN + HEADER_LEN + XA_SUB_LEN + USER_LEN + EDC_LEN + ECC_LEN == SECTOR

SYNC = b"\x00" + b"\xFF" * 10 + b"\x00"  # 12 bytes
MODE2 = 0x02
FORM2_BIT = 0x20

# CUE regexes — strict single-track MODE2/2352, INDEX 01 00:00:00.
_RE_FILE = re.compile(r'^\s*FILE\s+"([^"]+)"\s+(BINARY|BINARY/WAVE|WAVE|AIFF|MOTOROLA)\s*$')
_RE_TRACK = re.compile(r'^\s*TRACK\s+(\d+)\s+([A-Z0-9/]+)\s*$')
_RE_INDEX = re.compile(r'^\s*INDEX\s+(\d+)\s+(\d+):(\d+):(\d+)\s*$')


class _CueError(ValueError):
    """Refusal from a malformed .cue. Becomes a structural red at check 1."""


@dataclass(frozen=True, slots=True)
class XASector:
    """One validated Mode-2 sector with its complete user payload."""

    index: int
    form: int
    file_number: int
    channel_number: int
    submode: int
    coding_info: int
    payload: bytes


def _validate_mode2_sector(
    raw: bytes, abs_sec: int
) -> tuple[int, int, int, int, int]:
    """Validate the sector envelope and return XA metadata plus form."""
    if len(raw) != SECTOR:
        raise ValueError(
            f"ps1-bincue: sector {abs_sec} short read ({len(raw)} < {SECTOR})"
        )
    if raw[:SYNC_LEN] != SYNC:
        raise ValueError(
            f"ps1-bincue: sector {abs_sec} bad sync pattern "
            f"(got {raw[:SYNC_LEN].hex()})"
        )
    if raw[SYNC_LEN + 3] != MODE2:
        raise ValueError(
            f"ps1-bincue: sector {abs_sec} mode {raw[SYNC_LEN + 3]} != 2 "
            "(Mode 1 / audio are out of scope)"
        )

    xa_start = SYNC_LEN + HEADER_LEN
    first = raw[xa_start : xa_start + XA_COPY_LEN]
    repeated = raw[xa_start + XA_COPY_LEN : xa_start + XA_SUB_LEN]
    if first != repeated:
        raise ValueError(
            f"ps1-bincue: sector {abs_sec} XA subheader copies differ "
            f"({first.hex()} != {repeated.hex()})"
        )
    form = 2 if first[2] & FORM2_BIT else 1
    return first[0], first[1], first[2], first[3], form


def _parse_msf(m: int, s: int, f: int) -> int:
    """CD-ROM MSF (minute, second, frame) -> sector index (1 frame = 1 sector)."""
    if not (0 <= m <= 99 and 0 <= s <= 59 and 0 <= f <= 74):
        raise _CueError(f"invalid MSF {m:02d}:{s:02d}:{f:02d}")
    return ((m * 60) + s) * 75 + f


def _parse_cue(cue_path: Path) -> tuple[str, int]:
    """Parse a PS1-style .cue: must be a single data track MODE2/2352
    with INDEX 01 00:00:00. Returns (bin_filename, start_sector).

    Refusals (structural): no FILE line, multi-track, audio track,
    non-MODE2/2352, no INDEX 01, non-zero INDEX 01 start.
    """
    text = cue_path.read_text(encoding="utf-8", errors="replace")
    bin_name: str | None = None
    track_mode: str | None = None
    saw_track = False
    saw_index01 = False
    index01_start: int | None = None

    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()  # CUE comments are //
        if not line:
            continue
        m = _RE_FILE.match(line)
        if m:
            if bin_name is not None:
                raise _CueError("cue: multiple FILE lines (multi-bin discs out of scope)")
            bin_name = m.group(1)
            continue
        m = _RE_TRACK.match(line)
        if m:
            if saw_track:
                raise _CueError("cue: multiple TRACK lines (multi-track discs out of scope)")
            _num, mode = m.group(1), m.group(2)
            if mode != "MODE2/2352":
                raise _CueError(
                    f"cue: track mode {mode!r} out of scope "
                    "(only raw Mode 2 data is supported; Mode 1 / audio are separate rows)"
                )
            track_mode = mode
            saw_track = True
            continue
        m = _RE_INDEX.match(line)
        if m:
            if not saw_track:
                raise _CueError("cue: INDEX before TRACK")
            idx = int(m.group(1))
            start = _parse_msf(int(m.group(2)), int(m.group(3)), int(m.group(4)))
            if idx == 1:
                saw_index01 = True
                index01_start = start
            elif idx == 0:
                # INDEX 00 = pregap; must be 00:00:00 for a fresh data track
                if start != 0:
                    raise _CueError(f"cue: INDEX 00 pregap at {start} (only 00:00:00 supported)")
            else:
                raise _CueError(f"cue: INDEX {idx} out of scope (only INDEX 00/01)")
            continue
        # Unknown / unsupported line
        if line.startswith(("PREGAP", "POSTGAP", "TITLE", "PERFORMER", "REM",
                            "FLAGS", "CATALOG", "CDTEXTFILE", "ISRC")):
            raise _CueError(f"cue: {line.split()[0]} directive out of scope")

    if bin_name is None:
        raise _CueError("cue: no FILE line")
    if not saw_track or track_mode != "MODE2/2352":
        raise _CueError("cue: no MODE2/2352 data track")
    if not saw_index01 or index01_start != 0:
        raise _CueError("cue: INDEX 01 must be at 00:00:00")
    return bin_name, index01_start


class Mode2XASource:
    """Lazy ByteSource plus complete sector access for a Mode-2 XA track.

    Nothing is materialized (DESIGN §1): `read_at` maps output offsets
    to (sector index, sector offset) and reads each 2352-byte sector
    from the underlying raw .bin on demand. A one-sector cache keeps
    sequential reads within a sector from re-reading the raw bytes.

    `read_at` is the fixed 2048-byte cooked/LBA view required for ISO9660
    composition. `read_sector` is the lossless XA view: it returns all
    2048 Form-1 or 2324 Form-2 payload bytes and the repeated subheader's
    metadata. The eager form map contains one byte per sector, not payload.
    """

    def __init__(
        self,
        raw: ByteSource,
        start_sector: int,
        n_sectors: int,
        forms: bytes,
    ) -> None:
        if len(forms) != n_sectors or any(form not in (1, 2) for form in forms):
            raise ValueError("ps1-bincue: invalid prevalidated sector-form map")
        self._raw = raw
        self._start = start_sector
        self._n = n_sectors
        self._forms = forms
        self._cache_i = -1
        self._cache_sector: XASector | None = None

    def size(self) -> int:
        return self._n * USER_LEN

    def sector_count(self) -> int:
        """Number of sectors in the data track."""
        return self._n

    def sector_form(self, index: int) -> int:
        """Return 1 or 2 for a validated track-relative sector index."""
        self._check_sector_index(index)
        return self._forms[index]

    def form2_sectors(self) -> Iterator[int]:
        """Iterate track-relative indices of every Mode-2 Form-2 sector."""
        return (index for index, form in enumerate(self._forms) if form == 2)

    def _check_sector_index(self, index: int) -> None:
        if index < 0 or index >= self._n:
            raise ValueError(
                f"sector index {index} out of bounds (sector count {self._n})"
            )

    def read_sector(self, index: int) -> XASector:
        """Read one complete XA user payload and its subheader metadata.

        `index` is relative to the data track. Payload length is 2048 for
        Form 1 and 2324 for Form 2.
        """
        self._check_sector_index(index)
        if index == self._cache_i:
            assert self._cache_sector is not None
            return self._cache_sector
        abs_sec = self._start + index
        raw = self._raw.read_at(abs_sec * SECTOR, SECTOR)
        sector = self._sector_from_raw(index, raw)
        self._cache_i = index
        self._cache_sector = sector
        return sector

    def _sector_from_raw(self, index: int, raw: bytes) -> XASector:
        """Decode one pre-indexed raw sector without performing I/O."""
        abs_sec = self._start + index
        file_number, channel_number, submode, coding_info, form = (
            _validate_mode2_sector(raw, abs_sec)
        )
        if form != self._forms[index]:
            raise ValueError(
                f"ps1-bincue: sector {abs_sec} form changed after validation "
                f"({self._forms[index]} -> {form})"
            )
        payload_len = FORM2_USER_LEN if form == 2 else USER_LEN
        payload_start = SYNC_LEN + HEADER_LEN + XA_SUB_LEN
        sector = XASector(
            index=index,
            form=form,
            file_number=file_number,
            channel_number=channel_number,
            submode=submode,
            coding_info=coding_info,
            payload=bytes(raw[payload_start : payload_start + payload_len]),
        )
        return sector

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
            raw_start = (self._start + first_sector) * SECTOR
            raw_batch = self._raw.read_at(raw_start, batch_count * SECTOR)
            for batch_index in range(batch_count):
                sector_index = first_sector + batch_index
                raw_offset = batch_index * SECTOR
                raw = raw_batch[raw_offset : raw_offset + SECTOR]
                sector = self._sector_from_raw(sector_index, raw)
                self._cache_i = sector_index
                self._cache_sector = sector
                block = sector.payload
                block_offset = within if batch_index == 0 else 0
                take = min(USER_LEN - block_offset, stop - pos)
                out += block[block_offset : block_offset + take]
                pos += take
                if pos == stop:
                    break
        return bytes(out)


def sniff(source: ByteSource) -> bool:
    """True when the source begins with a CD-ROM Mode 2 sector.

    The full format is confirmed by normalize_ps1_bincue (which needs the
    sibling .cue to know the data-track start). This is a lightweight
    pre-filter; false positives are not dangerous (normalize fails fast).
    """
    if source.size() < SYNC_LEN + HEADER_LEN:
        return False
    return (
        source.read_at(0, SYNC_LEN) == SYNC
        and source.read_at(SYNC_LEN + 3, 1) == bytes((MODE2,))
    )


def _resolve_pair(source) -> tuple[ByteSource, Path]:
    """Return (bin ByteSource, .cue path). The source must be a path or
    a FileSource — we need the on-disk .bin to find its sibling .cue.

    A bare ByteSource with no path is refused (composition principle:
    ps1-bincue is a path-bound format; the .bin/.cue pair is the file
    on disk that carries the data).
    """
    if isinstance(source, FileSource):
        bin_path = source.path
    elif isinstance(source, (str, Path)):
        bin_path = Path(source)
    else:
        raise ValueError(
            "ps1-bincue: requires a path to the .bin (the .cue is its sibling) — "
            "raw ByteSources without a path are out of scope for this unit"
        )
    cue_path = bin_path.with_suffix(".cue")
    if not cue_path.exists():
        raise FileNotFoundError(f"ps1-bincue: no .cue sibling at {cue_path}")
    return FileSource(bin_path), cue_path


def normalize_ps1_bincue(source) -> ByteView:
    """Map a PS1 .bin/.cue to a cooked ByteView with lossless XA access.

    Accepts a path (str/Path) to the .bin or a FileSource over the .bin.
    Resolves the sibling .cue, parses the single data track, and returns
    a lazy ByteView backed by `Mode2XASource`. The caller may compose the
    fixed 2048-byte `read_at` view with `iso9660`, or call `read_sector`
    for each complete 2048/2324-byte XA payload (DESIGN §1).

    Refusals (structural reds): no .cue sibling, multi-track, audio,
    non-MODE2/2352, bad INDEX 01, sync mismatch, mode != 2, .bin
    not a multiple of 2352, or mismatched XA subheader copies.
    """
    src, cue_path = _resolve_pair(source)
    bin_name, start_sector = _parse_cue(cue_path)
    # The .cue's FILE name is informational; we already have the .bin
    # path from the caller. If the names disagree, that's a structural
    # red (the .bin must be the file the .cue describes).
    if bin_name != src.path.name:
        raise _CueError(
            f"cue: FILE {bin_name!r} does not match the supplied .bin {src.path.name!r}"
        )

    bin_size = src.size()
    if bin_size == 0:
        raise ValueError("ps1-bincue: empty .bin")
    if bin_size % SECTOR != 0:
        raise ValueError(
            f"ps1-bincue: .bin size {bin_size} not a multiple of {SECTOR}"
        )
    n_raw = bin_size // SECTOR
    n_data = n_raw - start_sector
    if n_data <= 0:
        raise ValueError(
            f"ps1-bincue: data track start {start_sector} >= total sectors {n_raw}"
        )

    # Eager structural pass: validate sync + mode on every data sector
    # at normalize time, so a corrupted sector surfaces as a check-1
    # structural red (verify.py wraps normalize_fn in try/except) rather
    # than a check-4 fidelity error mid-read. The user stream is NOT
    # materialized — these reads are discarded immediately.
    forms = bytearray(n_data)
    for batch_start in range(0, n_data, _RAW_BATCH_SECTORS):
        batch_count = min(_RAW_BATCH_SECTORS, n_data - batch_start)
        abs_start = start_sector + batch_start
        raw_batch = src.read_at(abs_start * SECTOR, batch_count * SECTOR)
        for batch_index in range(batch_count):
            i = batch_start + batch_index
            abs_sec = start_sector + i
            raw_offset = batch_index * SECTOR
            raw = raw_batch[raw_offset : raw_offset + SECTOR]
            *_metadata, form = _validate_mode2_sector(raw, abs_sec)
            forms[i] = form

    return ByteView(
        source=Mode2XASource(src, start_sector, n_data, bytes(forms)),
        format="ps1-bincue",
    )
