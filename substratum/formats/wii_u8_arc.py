"""Wii U8 archive filesystem normalizer (NORMALIZERS.md row `wii-u8-arc`).

Scope:
- Parses uncompressed U8 archives (`.arc`) and walks their node table into a FileTree.
- Refuses rather than guesses (structural red): YAZ0/SZS-compressed U8, bad tag, root not a dir,
  node table or string table out of bounds, cyclic directory sizes, non-ASCII names,
  and empty/dot/traversal path components.

Runtime is stdlib-only per DESIGN.md § 4.
"""

from __future__ import annotations

import struct

from substratum.contract import ByteSource, FileEntry, FileSource, FileTree

__all__ = ["sniff", "normalize_wii_u8_arc"]

_TAG = 0x55AA382D
_HEADER_LEN = 32
_NODE_SIZE = 12

def sniff(source: ByteSource) -> bool:
    """True when the source is a Wii U8 archive (magic 0x55AA382D at 0x00)."""
    if source.size() < _HEADER_LEN:
        return False
    magic = struct.unpack(">I", source.read_at(0, 4))[0]
    return magic == _TAG

def _read_name(metadata: bytes, strtab_base: int, name_off: int) -> str:
    """Decode a null-terminated ASCII name from the U8 string table."""
    start = strtab_base + name_off
    if start >= len(metadata):
        raise ValueError(f"name offset {name_off} past end of string table")
    end = metadata.find(b"\x00", start)
    if end < 0:
        raise ValueError(f"name at offset {name_off} has no null terminator")
    raw = metadata[start:end]
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(f"non-ASCII bytes in U8 name {raw!r}") from exc

def _walk(metadata: bytes, n_nodes: int, src_size: int) -> list[FileEntry]:
    """Walk the U8 node table into a flat list of FileEntries.

    U8 node table starts at 0x20. Each node is 12 bytes.
    String table begins at 0x20 + n_nodes * 12.
    """
    strtab_base = n_nodes * _NODE_SIZE
    entries: list[FileEntry] = []

    def _node(i: int) -> tuple[int, str, int, int]:
        """Return (type, name, f1, f2) for 1-based node index i."""
        base = (i - 1) * _NODE_SIZE
        node = metadata[base : base + _NODE_SIZE]
        name_off = int.from_bytes(node[1:4], "big")
        f1 = struct.unpack(">I", node[4:8])[0]
        f2 = struct.unpack(">I", node[8:12])[0]
        name = _read_name(metadata, strtab_base, name_off)
        return node[0], name, f1, f2

    def _recurse(dir_index: int, last_index: int, prefix: str) -> None:
        """Emit children of node `dir_index` whose scope is [dir_index + 1, last_index] inclusive."""
        i = dir_index + 1
        while i <= last_index:
            ntype, name, f1, f2 = _node(i)
            if not name or name in {".", ".."} or "/" in name or "\\" in name:
                raise ValueError(f"invalid U8 path component {name!r}")
            path = f"{prefix}/{name}" if prefix else name
            if ntype == 0:  # file
                # f1 = absolute file offset, f2 = file size
                if f1 + f2 > src_size:
                    raise ValueError(
                        f"file {name!r} range [{f1}, {f1 + f2}) exceeds "
                        f"archive size {src_size}"
                    )
                entries.append(FileEntry(path=path, kind="file", offset=f1, size=f2))
                i += 1
            elif ntype == 1:  # directory
                # f1 = parent index (must be dir_index)
                # f2 = last child index (inclusive next)
                if f1 != dir_index:
                    raise ValueError(
                        f"directory {name!r} parent={f1} != enclosing dir {dir_index}"
                    )
                if f2 < i or f2 > n_nodes:
                    raise ValueError(
                        f"directory {name!r} has invalid next/last={f2} "
                        f"(index {i}, count {n_nodes})"
                    )
                entries.append(FileEntry(path=path, kind="dir", offset=0, size=0))
                _recurse(i, f2, path)
                i = f2 + 1  # jump past the closed subdirectory
            else:
                raise ValueError(f"node {i} ({name!r}) has unknown type {ntype}")

    root_type, _, root_parent, root_next = _node(1)
    if root_type != 1:
        raise ValueError(f"root node is not a directory (type {root_type})")
    if root_parent not in (0, 1):
        raise ValueError(f"root node parent={root_parent} not in (0, 1)")
    _recurse(1, root_next, "")
    return entries

def normalize_wii_u8_arc(source) -> FileTree:
    """Parse a Wii U8 archive into a FileTree.

    Accepts a path (str/Path) or a ByteSource.
    """
    src = source if isinstance(source, ByteSource) else FileSource(source)
    src_size = src.size()

    if src_size < _HEADER_LEN:
        raise ValueError("source too small to contain a Wii U8 header")

    header = src.read_at(0, _HEADER_LEN)
    tag, rootnode_offset, header_size, data_offset = struct.unpack(">IIII", header[:16])

    if tag != _TAG:
        raise ValueError(f"not a Wii U8 archive (magic {tag:#010x})")
    if rootnode_offset != 0x20:
        raise ValueError(f"invalid rootnode_offset {rootnode_offset:#x} (must be 0x20)")
    if data_offset % 0x40 != 0:
        raise ValueError(f"data_offset {data_offset:#x} is not aligned to 0x40")
    if rootnode_offset + header_size > src_size:
        raise ValueError("U8 header + table exceeds archive size")

    # Read node and string tables
    metadata = src.read_at(rootnode_offset, header_size)
    if len(metadata) < _NODE_SIZE:
        raise ValueError("U8 node table too small for root node")

    n_nodes = struct.unpack(">I", metadata[8:12])[0]
    if n_nodes == 0:
        raise ValueError("U8 root node count is zero")
    if n_nodes * _NODE_SIZE > len(metadata):
        raise ValueError("U8 node table exceeds metadata size")

    entries = _walk(metadata, n_nodes, src_size)
    return FileTree(source=src, format="wii-u8-arc", entries=tuple(entries))
