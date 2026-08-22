"""Xbox XDVDFS filesystem normalizer (NORMALIZERS.md row `xdvdfs`).

Scope:
- Parses a plain XDVDFS image (descriptor at 0x10000 by default) into a
  FileTree; an embedded retail image may be offset by `base_offset`.
- Refuses rather than guesses (structural red): bad magic/tail, root table
  out of bounds, bad LCRS pointers, bad file ranges, invalid names.

Runtime is stdlib-only per DESIGN.md § 4.
"""

from __future__ import annotations

import struct

from substratum.contract import ByteSource, FileEntry, FileSource, FileTree

__all__ = ["sniff", "normalize_xdvdfs"]

_MAGIC = b"MICROSOFT*XBOX*MEDIA"
_SECTOR = 0x800
_DESC_OFFSET = 0x10000
_MAGIC_TAIL_OFFSET = 0x7EC
_PAD_SHORT = 0xFFFF
_DIR_ATTR = 0x10
_NAME_MAX = 255

# Known descriptor base offsets (design spec § 9): a plain `.xiso` carries
# the descriptor at 0x10000 (base 0); a full retail XGD dump embeds the game
# partition after the decoy DVD-Video region. Probe order is plain first so
# a trimmed image never pays for the retail probes.
_KNOWN_BASE_OFFSETS = (0, 0x18300000, 0x0FD90000, 0x02080000)


def _magic_at(source: ByteSource, base_offset: int) -> bool:
    desc_offset = base_offset + _DESC_OFFSET
    if source.size() < desc_offset + _SECTOR:
        return False
    return source.read_at(desc_offset, len(_MAGIC)) == _MAGIC


def _probe_base_offset(source: ByteSource) -> int:
    """The first known base whose descriptor magic matches.

    Raises when none matches — the dispatcher only calls this after a
    matching sniff, so in dispatch the raise is unreachable; a pinned
    caller gets a clean structural refusal instead of a wrong parse.
    """
    for base in _KNOWN_BASE_OFFSETS:
        if _magic_at(source, base):
            return base
    known = ", ".join(hex(base) for base in _KNOWN_BASE_OFFSETS)
    raise ValueError(f"no XDVDFS descriptor at any known base offset ({known})")


def sniff(source: ByteSource, *, base_offset: int | None = None) -> bool:
    """True when the source contains an XDVDFS volume descriptor.

    ``base_offset`` shifts the expected descriptor to ``base_offset + 0x10000``.
    The default ``None`` probes the four known bases (plain `.xiso` and the
    three retail XGD embeddings), which is what lets ``normalize()`` claim a
    retail Xbox disc before ``iso9660`` claims its decoy DVD-Video partition.
    An explicit ``int`` pins exactly one offset and preserves the pre-probe
    meaning byte-for-byte.
    """
    if base_offset is not None:
        if base_offset < 0:
            raise ValueError(f"base_offset must be >= 0 (got {base_offset})")
        return _magic_at(source, base_offset)
    return any(_magic_at(source, base) for base in _KNOWN_BASE_OFFSETS)


def _read_name(table: bytes, entry_offset: int) -> str:
    """Decode an ASCII entry name from a directory table."""
    if entry_offset + 0x0E > len(table):
        raise ValueError("directory entry exceeds table size")
    name_len = table[entry_offset + 0x0D]
    if name_len == 0 or name_len > _NAME_MAX:
        raise ValueError(f"invalid entry name length {name_len}")
    end = entry_offset + 0x0E + name_len
    if end > len(table):
        raise ValueError("directory entry name exceeds table size")
    raw = table[entry_offset + 0x0E : end]
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(f"non-ASCII bytes in XDVDFS name {raw!r}") from exc


def _walk_table(
    src: ByteSource,
    table: bytes,
    entry_offset: int,
    prefix: str,
    src_size: int,
    entries: list[FileEntry],
    visited: set[int],
    dir_tables_seen: set[int],
    base_offset: int,
) -> None:
    """Walk an XDVDFS directory table using the LCRS binary-tree format.

    `visited` is per-table (entry offsets are table-relative); it catches
    LCRS pointer cycles within one table. `dir_tables_seen` is image-wide
    (absolute byte offsets of directory tables already entered); it catches
    a nested directory whose table points back at an ancestor's — a cross-
    table cycle the per-table set cannot see (mirrors iso9660's discipline).
    XDVDFS gives each directory its own fresh table, so a repeated table
    offset is never valid.

    The LCRS `*_offset` fields count in 4-byte dwords; the real tree uses
    these counts to reach a child/sibling offset within the current table,
    not raw byte offsets. Rejecting odd counts is a false structural check
    and must not fire on valid retail images.
    """
    if entry_offset in visited:
        raise ValueError(f"directory traversal cycle at offset {entry_offset}")
    if entry_offset < 0 or entry_offset >= len(table):
        return
    if entry_offset + 2 > len(table):
        raise ValueError(f"directory entry at {entry_offset} extends past table")

    l_offset = struct.unpack_from("<H", table, entry_offset)[0]
    if l_offset == _PAD_SHORT:
        return

    if entry_offset + 0x0E > len(table):
        raise ValueError(f"directory entry at {entry_offset} is truncated")

    r_offset = struct.unpack_from("<H", table, entry_offset + 2)[0]
    start_sector = struct.unpack_from("<I", table, entry_offset + 4)[0]
    file_size = struct.unpack_from("<I", table, entry_offset + 8)[0]
    attrs = table[entry_offset + 0x0C]
    name = _read_name(table, entry_offset)
    if name in {".", ".."} or "/" in name or "\\" in name:
        raise ValueError(f"invalid XDVDFS path component {name!r}")

    path = f"{prefix}/{name}" if prefix else name
    visited.add(entry_offset)

    if l_offset != 0:
        child_offset = l_offset * 4
        if child_offset >= len(table):
            raise ValueError(f"left child offset {l_offset} exceeds table size")
        _walk_table(
            src,
            table,
            child_offset,
            prefix,
            src_size,
            entries,
            visited,
            dir_tables_seen,
            base_offset,
        )

    if attrs & _DIR_ATTR:
        if file_size == 0:
            raise ValueError(f"directory {name!r} has zero size")
        nested_offset = base_offset + start_sector * _SECTOR
        if nested_offset + file_size > src_size:
            raise ValueError("descriptor exceeds source size")
        if nested_offset in dir_tables_seen:
            raise ValueError(f"directory cycle at table offset {nested_offset}")
        dir_tables_seen.add(nested_offset)
        entries.append(FileEntry(path=path, kind="dir", offset=0, size=0))
    else:
        absolute_offset = base_offset + start_sector * _SECTOR
        if absolute_offset + file_size > src_size:
            raise ValueError(
                f"file {name!r} range [{absolute_offset}, "
                f"{absolute_offset + file_size}) exceeds source size {src_size}"
            )
        entries.append(
            FileEntry(path=path, kind="file", offset=absolute_offset, size=file_size)
        )

    if attrs & _DIR_ATTR:
        subtable = src.read_at(nested_offset, file_size)
        _walk_table(src, subtable, 0, path, src_size, entries, set(), dir_tables_seen, base_offset)

    if r_offset != 0:
        if r_offset == _PAD_SHORT:
            return
        sibling_offset = r_offset * 4
        if sibling_offset >= len(table):
            raise ValueError(f"right sibling offset {r_offset} exceeds table size")
        _walk_table(src, table, sibling_offset, prefix, src_size, entries, visited, dir_tables_seen, base_offset)


def normalize_xdvdfs(source, *, base_offset: int | None = None) -> FileTree:
    """Parse an XDVDFS image into a FileTree.

    ``base_offset`` shifts the descriptor, root table, and file payloads within a
    larger dump (e.g. a retail XGD1 image whose game partition starts at a
    non-zero embedded offset). The default ``None`` probes the four known
    bases (plain `.xiso` first, then the three retail XGD embeddings) so
    ``normalize()`` reaches retail Xbox discs without a pin; an explicit
    ``int`` keeps plain XISO handling byte-for-byte unchanged.
    """
    src = source if isinstance(source, ByteSource) else FileSource(source)
    if base_offset is None:
        base_offset = _probe_base_offset(src)
    if base_offset < 0:
        raise ValueError(f"base_offset must be >= 0 (got {base_offset})")

    src_size = src.size()
    desc_offset = base_offset + _DESC_OFFSET

    if src_size < desc_offset + _SECTOR:
        raise ValueError("descriptor exceeds source size")

    try:
        desc = src.read_at(desc_offset, _SECTOR)
    except ValueError as exc:
        raise ValueError("descriptor exceeds source size") from exc

    if desc[: len(_MAGIC)] != _MAGIC:
        raise ValueError("not an XDVDFS image (bad descriptor magic)")

    root_sector = struct.unpack_from("<I", desc, 0x14)[0]
    root_size = struct.unpack_from("<I", desc, 0x18)[0]
    if root_sector == 0 or root_size == 0:
        raise ValueError("root directory size is invalid")
    if root_size % _SECTOR != 0:
        raise ValueError("root directory size is not sector-aligned")
    root_offset = base_offset + root_sector * _SECTOR
    if root_offset + root_size > src_size:
        raise ValueError("root directory table exceeds source size")

    if desc[_MAGIC_TAIL_OFFSET : _MAGIC_TAIL_OFFSET + len(_MAGIC)] != _MAGIC:
        raise ValueError("not an XDVDFS image (descriptor tail magic mismatch)")

    root_table = src.read_at(root_offset, root_size)
    entries: list[FileEntry] = []
    _walk_table(src, root_table, 0, "", src_size, entries, set(), {root_offset}, base_offset)
    return FileTree(source=src, format="xdvdfs", entries=tuple(entries))
