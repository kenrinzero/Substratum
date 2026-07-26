"""GameCube FST disc-filesystem normalizer (S2; NORMALIZERS.md row `gc-fst`).

Scope — deliberately unit-bounded (mirrors iso9660's discipline):
- The user-data filesystem only: parse the FST at disc header offset
  0x424 (size 0x428) and walk its node table into a FileTree.
- Disc-system files (`sys/`: boot.bin, bi2.bin, apploader.img, main.dol,
  fst.bin) are fixed disc-header regions, NOT FST entries — wit exposes
  them as a virtual view; this unit does not synthesize them.
- Refuses rather than guesses (structural red): Wii discs (different
  magic, deferred keyed platform), TGC (a standalone TGC lacks the GC
  magic and is refused; an embedded GCM whose FST fields are bogus dies at
  the bounds checks), FST out of bounds, malformed node tables, non-ASCII
  names, and empty/dot/traversal path components.

Runtime is stdlib-only per DESIGN.md § 4.

Format reference: yagcd §13 (hitmen.c02.at/files/yagcd/yagcd/chap13.html).
The load-bearing finding: FST nodes are 0x0C (12) bytes, NOT 0x20 —
confirmed against yagcd §13.4 and byte-exact wit cross-check.
"""

from __future__ import annotations

import struct

from substratum.contract import ByteSource, FileEntry, FileSource, FileTree

__all__ = ["sniff", "normalize_gc_fst"]

_GC_MAGIC = 0xC2339F3D
_WII_MAGIC = 0x5D1C9EA3
_MAGIC_OFF = 0x01C
_FST_OFF = 0x424
_FST_SIZE = 0x428
_NODE_SIZE = 0x0C  # 12 bytes per FST entry (load-bearing: NOT 0x20)


def sniff(source: ByteSource) -> bool:
    """True when the source is a GameCube disc (GC magic at 0x01c).

    Wii magic is NOT sniffed (Wii partitions are a deferred keyed platform).
    """
    if source.size() < _MAGIC_OFF + 4:
        return False
    magic = struct.unpack(">I", source.read_at(_MAGIC_OFF, 4))[0]
    return magic == _GC_MAGIC


def _read_name(fst: bytes, strtab_base: int, name_off: int) -> str:
    """Decode a null-terminated ASCII name from the FST string table."""
    start = strtab_base + name_off
    if start >= len(fst):
        raise ValueError(f"name offset {name_off} past end of string table")
    end = fst.find(b"\x00", start)
    if end < 0:
        raise ValueError(f"name at offset {name_off} has no null terminator")
    raw = fst[start:end]
    try:
        name = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(f"non-ASCII bytes in FST name {raw!r}") from exc
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise ValueError(f"invalid FST path component {name!r}")
    return name


def _walk(fst: bytes, src_size: int) -> list[FileEntry]:
    """Walk the FST node table into a flat list of FileEntries.

    The FST is a table of 0x0C-byte nodes followed by a string table. Node
    layout (big-endian): byte 0 = type (0=file, 1=dir); bytes 1-3 = name
    offset into the string table; bytes 4-7 = file offset (absolute from
    disc start) / dir parent index; bytes 8-11 = file size / dir next-index.
    Root is node 0: type=dir, name="" (offset 0), parent=0, next=node_count.

    Directory nesting is handled by the standard FST traversal: a
    directory's direct children are the contiguous nodes [self+1, next),
    recursed in order. The flat retail fixture has no nested directories;
    the on-demand nested fixture exercises close/resume and
    sibling-after-subtree behavior through the same path.
    """
    if len(fst) < _NODE_SIZE:
        raise ValueError("FST too small for root node")
    root_type = fst[0]
    if root_type != 1:
        raise ValueError(f"FST root node is not a directory (type {root_type})")
    node_count = struct.unpack(">I", fst[8:12])[0]
    if node_count == 0:
        raise ValueError("FST root node count is zero")
    table_len = node_count * _NODE_SIZE
    if table_len > len(fst):
        raise ValueError(
            f"FST node table ({node_count} x {_NODE_SIZE} = {table_len}) "
            f"exceeds declared FST size {len(fst)}"
        )
    strtab_base = table_len

    entries: list[FileEntry] = []

    def _node(i: int) -> tuple[int, str, int, int]:
        """Return (type, name, field1, field2) for node index i."""
        base = i * _NODE_SIZE
        node = fst[base : base + _NODE_SIZE]
        name_off = int.from_bytes(node[1:4], "big")
        f1 = struct.unpack(">I", node[4:8])[0]
        f2 = struct.unpack(">I", node[8:12])[0]
        return node[0], _read_name(fst, strtab_base, name_off), f1, f2

    def _recurse(dir_index: int, next_index: int, prefix: str) -> None:
        """Emit children of node `dir_index` whose scope is [dir_index, next).

        Children of a directory are the contiguous nodes immediately after
        it, up to (but not including) the directory's own `next` index.
        Subdirectories recurse with their own next boundary.
        """
        i = dir_index + 1
        while i < next_index:
            ntype, name, f1, f2 = _node(i)
            path = f"{prefix}/{name}" if prefix else name
            if ntype == 0:  # file
                if f1 + f2 > src_size:
                    raise ValueError(
                        f"file {name!r} range [{f1}, {f1 + f2}) exceeds "
                        f"disc size {src_size}"
                    )
                entries.append(FileEntry(path=path, kind="file", offset=f1, size=f2))
                i += 1
            elif ntype == 1:  # directory
                # f1 = parent index (must be dir_index), f2 = next (scope end)
                if f1 != dir_index:
                    raise ValueError(
                        f"directory {name!r} parent={f1} != enclosing dir {dir_index}"
                    )
                if f2 <= i or f2 > node_count:
                    raise ValueError(
                        f"directory {name!r} has invalid next={f2} "
                        f"(index {i}, count {node_count})"
                    )
                entries.append(FileEntry(path=path, kind="dir", offset=0, size=0))
                _recurse(i, f2, path)
                i = f2  # jump past the closed subtree
            else:
                raise ValueError(f"node {i} ({name!r}) has unknown type {ntype}")

    root_next = node_count  # root's `next` field == total node count
    _recurse(0, root_next, "")
    return entries


def normalize_gc_fst(source) -> FileTree:
    """Parse a GameCube disc's FST into a FileTree.

    Accepts a path (str/Path) or a ByteSource.
    """
    src = source if isinstance(source, ByteSource) else FileSource(source)
    src_size = src.size()

    if src_size < _FST_SIZE + 4:
        raise ValueError("source too small to contain a GameCube header")

    magic = struct.unpack(">I", src.read_at(_MAGIC_OFF, 4))[0]
    if magic == _WII_MAGIC:
        raise ValueError("Wii disc (different magic) — not supported by gc-fst")
    if magic != _GC_MAGIC:
        raise ValueError(f"not a GameCube disc (magic {magic:#010x})")

    fst_off = struct.unpack(">I", src.read_at(_FST_OFF, 4))[0]
    fst_size = struct.unpack(">I", src.read_at(_FST_SIZE, 4))[0]

    if fst_size == 0:
        raise ValueError("FST size is zero")
    if fst_off + fst_size > src_size:
        raise ValueError(
            f"FST range [{fst_off}, {fst_off + fst_size}) exceeds disc size {src_size}"
        )
    fst = src.read_at(fst_off, fst_size)
    entries = _walk(fst, src_size)
    return FileTree(source=src, format="gc-fst", entries=tuple(entries))
