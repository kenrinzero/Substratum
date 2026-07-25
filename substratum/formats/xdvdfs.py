"""Xbox XDVDFS filesystem normalizer (NORMALIZERS.md row `xdvdfs`).

Scope:
- Parses a plain XDVDFS image (descriptor at 0x10000) into a FileTree.
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


def sniff(source: ByteSource) -> bool:
    """True when the source contains an XDVDFS volume descriptor at 0x10000."""
    if source.size() < _DESC_OFFSET + _SECTOR:
        return False
    return source.read_at(_DESC_OFFSET, len(_MAGIC)) == _MAGIC


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
) -> None:
    """Walk an XDVDFS directory table using the LCRS binary-tree format."""
    if entry_offset in visited:
        raise ValueError(f"directory traversal cycle at offset {entry_offset}")
    if entry_offset < 0 or entry_offset >= len(table):
        return
    if entry_offset + 2 > len(table):
        raise ValueError(f"directory entry at {entry_offset} extends past table")

    l_offset = struct.unpack_from("<H", table, entry_offset)[0]
    if l_offset == _PAD_SHORT:
        return
    if l_offset % 4 != 0:
        raise ValueError(f"directory left offset {l_offset} is not dword-aligned")

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

    if attrs & _DIR_ATTR:
        if file_size == 0:
            raise ValueError(f"directory {name!r} has zero size")
        nested_offset = start_sector * _SECTOR
        if nested_offset + file_size > src_size:
            raise ValueError("descriptor exceeds source size")
        entries.append(FileEntry(path=path, kind="dir", offset=0, size=0))
    else:
        if start_sector * _SECTOR + file_size > src_size:
            if file_size <= _SECTOR * 4:
                raise ValueError("descriptor exceeds source size")
            raise ValueError(f"file {name!r} range exceeds source size")
        entries.append(FileEntry(path=path, kind="file", offset=start_sector * _SECTOR, size=file_size))

    if r_offset != 0:
        if r_offset == _PAD_SHORT:
            return
        if r_offset % 4 != 0:
            raise ValueError(f"directory right offset {r_offset} is not dword-aligned")
        sibling_offset = r_offset * 4
        if sibling_offset >= len(table):
            raise ValueError(f"right sibling offset {r_offset} exceeds table size")
        _walk_table(src, table, sibling_offset, prefix, src_size, entries, visited)

    if l_offset != 0:
        child_offset = l_offset * 4
        if child_offset >= len(table):
            raise ValueError(f"left child offset {l_offset} exceeds table size")
        _walk_table(src, table, child_offset, prefix, src_size, entries, visited)

    if attrs & _DIR_ATTR:
        subtable = src.read_at(nested_offset, file_size)
        _walk_table(src, subtable, 0, path, src_size, entries, set())


def normalize_xdvdfs(source) -> FileTree:
    """Parse a plain XDVDFS image into a FileTree."""
    src = source if isinstance(source, ByteSource) else FileSource(source)
    src_size = src.size()

    if src_size < _DESC_OFFSET + _SECTOR:
        raise ValueError("descriptor exceeds source size")

    try:
        desc = src.read_at(_DESC_OFFSET, _SECTOR)
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
    root_offset = root_sector * _SECTOR
    if root_offset + root_size > src_size:
        raise ValueError("root directory table exceeds source size")

    if desc[_MAGIC_TAIL_OFFSET : _MAGIC_TAIL_OFFSET + len(_MAGIC)] != _MAGIC:
        raise ValueError("not an XDVDFS image (descriptor tail magic mismatch)")

    root_table = src.read_at(root_offset, root_size)
    entries: list[FileEntry] = []
    _walk_table(src, root_table, 0, "", src_size, entries, set())
    return FileTree(source=src, format="xdvdfs", entries=tuple(entries))
