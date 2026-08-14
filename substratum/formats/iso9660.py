"""ISO9660 disc-filesystem normalizer (S1; NORMALIZERS.md row `iso9660`).

Scope — deliberately unit-bounded:
- 2048-byte-per-sector images (mode1 / DVD-style). Raw 2352-byte mode2
  sector mapping is the ps1-bincue unit's substance, not this one's.
- Primary volume descriptor only: names are the PVD's recorded
  identifiers (version suffix stripped), no Joliet/Rock Ridge resolution.
- Refuses rather than guesses (structural red): multi-extent files,
  interleaved files, extended-attribute records, both-endian field
  mismatches, truncated/cross-block directory records, invalid path
  components, directory cycles.

Runtime is stdlib-only per DESIGN.md § 4.
"""

from __future__ import annotations

import struct

from substratum.contract import ByteSource, FileEntry, FileSource, FileTree

__all__ = ["sniff", "normalize_iso9660"]

SECTOR = 2048  # descriptor grid (ECMA-119 byte 32768); block size comes from the PVD
_PVD_TYPE = 1
_TERMINATOR = 255
_VDS_SCAN_CAP = 64  # sectors of descriptors before we declare the set unterminated

_FLAG_DIR = 0x02
_FLAG_MULTI_EXTENT = 0x80


def sniff(source: ByteSource) -> bool:
    if source.size() < 17 * SECTOR:
        return False
    return source.read_at(16 * SECTOR + 1, 5) == b"CD001"


def _both_endian_32(raw: bytes, what: str) -> int:
    le = struct.unpack("<I", raw[:4])[0]
    be = struct.unpack(">I", raw[4:8])[0]
    if le != be:
        raise ValueError(f"both-endian {what} mismatch: LE {le} != BE {be}")
    return le


def _record_extent_and_size(
    rec: bytes, fi: bytes, block: int, source_size: int, lba_base: int
) -> tuple[int, int]:
    """Resolve one directory record's both-endian extent/size pair.

    Tolerates *single-sided* mastering corruption (BACKLOG RE4 PAL, 2026):
    the staged 2021 re-master carries exactly one record whose little-endian
    fields are garbage (extent = the volume space itself) while the
    big-endian pair is structurally possible. When the two orders disagree,
    trust the side whose (extent, size) pair is possible in this source —
    and take that side's size too, since the corrupt order poisoned both
    its fields. A disagreement where both sides are possible (or neither)
    still refuses: ambiguity is never guessed away.
    """
    loc_le = struct.unpack("<I", rec[2:6])[0]
    loc_be = struct.unpack(">I", rec[6:10])[0]
    size_le = struct.unpack("<I", rec[10:14])[0]
    size_be = struct.unpack(">I", rec[14:18])[0]
    if loc_le == loc_be and size_le == size_be:
        return loc_le, size_le

    def possible(loc: int, size: int) -> bool:
        rel = loc - lba_base  # evaluate in track-relative space
        if rel < 0:
            return False
        if rel * block + size > source_size:
            return False
        return size == 0 or rel >= 16  # sectors 0-15 are the system area

    le_ok = possible(loc_le, size_le)
    be_ok = possible(loc_be, size_be)
    if le_ok == be_ok:
        raise ValueError(
            f"both-endian extent/size mismatch on {fi!r}: LE "
            f"({loc_le}, {size_le}) vs BE ({loc_be}, {size_be}) — no unique "
            "possible side"
        )
    return (loc_le, size_le) if le_ok else (loc_be, size_be)


def _validate_path_component(name: str) -> None:
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise ValueError(f"invalid ISO9660 path component {name!r}")


def _walk(
    src: ByteSource,
    block: int,
    root_extent: int,
    root_len: int,
    lba_base: int,
) -> list[FileEntry]:
    entries: list[FileEntry] = []
    seen: set[int] = set()
    stack: list[tuple[str, int, int]] = [("", root_extent, root_len)]
    while stack:
        prefix, extent, data_len = stack.pop()
        if extent in seen:
            raise ValueError(f"directory cycle at extent {extent}")
        seen.add(extent)
        data = src.read_at(extent * block, data_len)  # out of bounds -> structural
        pos = 0
        while pos < data_len:
            rec_len = data[pos]
            if rec_len == 0:
                # records never span sectors; a zero byte pads to the next one
                pos = (pos // block + 1) * block
                continue
            remaining = data_len - pos
            if rec_len > remaining:
                raise ValueError(
                    f"directory record claims {rec_len} bytes with only "
                    f"{remaining} remaining at extent {extent}+{pos}"
                )
            block_remaining = block - (pos % block)
            if rec_len > block_remaining:
                raise ValueError(
                    "directory record crosses logical block boundary at "
                    f"extent {extent}+{pos} ({rec_len} bytes, "
                    f"{block_remaining} remain)"
                )
            rec = data[pos : pos + rec_len]
            if len(rec) < 34 or rec_len < 33 + rec[32]:
                raise ValueError(f"truncated directory record at extent {extent}+{pos}")
            pos += rec_len
            len_fi = rec[32]
            fi = rec[33 : 33 + len_fi]
            if len_fi == 1 and fi in (b"\x00", b"\x01"):
                continue  # self / parent
            if rec[1]:
                raise ValueError(f"extended attribute record on {fi!r} unsupported")
            flags = rec[25]
            if flags & _FLAG_MULTI_EXTENT:
                raise ValueError(f"multi-extent file {fi!r} unsupported")
            if rec[26] or rec[27]:
                raise ValueError(f"interleaved file {fi!r} unsupported")
            loc, size = _record_extent_and_size(
                rec, fi, block, src.size(), lba_base
            )
            if loc < lba_base:
                raise ValueError(
                    f"extent location {loc} below the LBA base {lba_base} "
                    f"on {fi!r}"
                )
            loc -= lba_base
            name = fi.decode("latin-1")
            if not flags & _FLAG_DIR:
                name = name.split(";", 1)[0]
            _validate_path_component(name)
            path = prefix + name
            if flags & _FLAG_DIR:
                entries.append(FileEntry(path, "dir", loc * block, size))
                stack.append((path + "/", loc, size))
            else:
                entries.append(FileEntry(path, "file", loc * block, size))
    return entries


def normalize_iso9660(source, *, lba_base: int = 0) -> FileTree:
    """Walk one ISO9660 filesystem into a ``FileTree``.

    ``lba_base`` translates **disc-absolute** extent locations into this
    source's track-relative sector space (GD-ROM composition: Dreamcast
    data tracks are mastered with extents absolute from disc start, where
    the data track begins at LBA 45,000 — see ``saturn_dc_raw.lba_base``).
    The default ``0`` keeps track-relative images byte-for-byte unchanged.
    Descriptor *positions* (the volume-descriptor set at sector 16) are
    always track-relative.
    """
    src = source if isinstance(source, ByteSource) else FileSource(source)
    if lba_base < 0:
        raise ValueError(f"lba_base must be >= 0 (got {lba_base})")

    pvd = None
    for i in range(16, 16 + _VDS_SCAN_CAP):
        raw = src.read_at(i * SECTOR, SECTOR)
        if raw[1:6] != b"CD001":
            raise ValueError(f"volume descriptor {i} lacks CD001 standard identifier")
        if raw[0] == _TERMINATOR:
            break
        if raw[0] == _PVD_TYPE and pvd is None:
            pvd = raw
    else:
        raise ValueError(f"volume descriptor set unterminated after {_VDS_SCAN_CAP} sectors")
    if pvd is None:
        raise ValueError("no primary volume descriptor")

    block_le = struct.unpack("<H", pvd[128:130])[0]
    block_be = struct.unpack(">H", pvd[130:132])[0]
    if block_le != block_be:
        raise ValueError(f"both-endian block size mismatch: {block_le} != {block_be}")
    if block_le == 0 or SECTOR % block_le:
        raise ValueError(f"unsupported logical block size {block_le}")

    root = pvd[156:190]
    root_extent, root_len = _record_extent_and_size(
        root, b"<root>", block_le, src.size(), lba_base
    )
    if root_extent < lba_base:
        raise ValueError(
            f"root extent {root_extent} below the LBA base {lba_base}"
        )
    root_extent -= lba_base

    entries = _walk(src, block_le, root_extent, root_len, lba_base)
    return FileTree(source=src, format="iso9660", entries=tuple(entries))
