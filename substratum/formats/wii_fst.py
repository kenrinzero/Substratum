"""Wii decrypted-partition FST filesystem normalizer.

Input: a decrypted DATA-partition ``ByteView`` from ``wii-partition`` — a
``ByteSource`` / path whose bytes are the decrypted cluster payloads (or,
equivalently, a raw decrypted Wii DATA partition image).

Output: a ``FileTree`` over the user-data files declared by the partition's
FST (filesystem table). Per DESIGN.md §1 this is a filesystem layer only —
it does not decrypt (the caller composes ``wii-partition`` first) and does
not synthesize the fixed disc-system regions (boot.bin, bi2.bin, apploader,
main.dol, fst.bin) that wit exposes as a virtual view; those are not FST
entries.

Load-bearing format finding (the Wii analogue of gc-fst's "nodes are 0x0C"
finding): **Wii FST file offsets are word offsets, not byte offsets.** Every
offset/size field in the Wii DATA-partition header and every file-offset
field in a Wii FST node is stored as ``value`` and used as ``value << 2``
(byte = word × 4). GameCube FST offsets are byte offsets directly; gc-fst
uses them raw. This difference is why the two units stay independent rather
than sharing the walker — the offset transform is baked into the traversal.

Node format is otherwise identical to GameCube (yagcd §13.4): 0x0C-byte
nodes, byte 0 = type (0=file, 1=dir), bytes 1-3 = name offset into the
string table, bytes 4-7 = file offset (Wii: word) / dir parent, bytes 8-11 =
file size / dir next-index.

Runtime is stdlib-only per DESIGN.md §4.
"""

from __future__ import annotations

import struct

from substratum.contract import ByteSource, FileEntry, FileSource, FileTree

__all__ = ["sniff", "normalize_wii_fst"]

# Wii DATA-partition header field offsets (decrypted stream). Every value is
# word-based: byte offset = field_value << 2.
_FST_OFF_FIELD = 0x424
_FST_SIZE_FIELD = 0x428
_FST_MAX_FIELD = 0x42C
_HEADER_MIN = 0x440  # boot.bin is 0x440 bytes
_WORD_SHIFT = 2
_NODE_SIZE = 0x0C  # 12 bytes per FST node (same as GC; load-bearing yagcd §13.4)


def sniff(source: ByteSource) -> bool:
    """Heuristic: a decrypted Wii DATA partition has no fixed magic (the Wii
    disc magic lives in the encrypted outer header that wii-disc validated).
    The dispatcher reaches this sniffer via an explicit ``format=`` pin in
    practice; composition from wii-partition is the documented path.

    To avoid false-positives in auto-detect (CHD, ISO9660, etc. also start
    with printable bytes), we require: (1) a printable 6-byte disc ID at
    offset 0, (2) NOT a GameCube disc (no GC magic at 0x1C — gc-fst owns
    those), and (3) a plausible FST location — the word-shifted header field
    at 0x424 must point to an offset within the source. This three-gate
    heuristic is still weak (the format has no true magic); explicit
    ``format="wii-fst"`` is the reliable dispatch.
    """
    if source.size() < _HEADER_MIN + 4:
        return False
    head = source.read_at(0, 6)
    if not all(0x20 <= b < 0x7F for b in head):
        return False
    # Reject GameCube discs (magic 0xC2339F3D at 0x1C) — gc-fst owns those.
    gc_magic = struct.unpack(">I", source.read_at(0x1C, 4))[0]
    if gc_magic == 0xC2339F3D:
        return False
    # Require a plausible FST location: the word-shifted field at 0x424 must
    # land within the source. This rejects unrelated printable-header files
    # (CHD's "MComprHD", ISO9660 volume IDs, etc.) whose bytes at 0x424 are
    # arbitrary.
    fst_off = struct.unpack(">I", source.read_at(_FST_OFF_FIELD, 4))[0] << _WORD_SHIFT
    if fst_off == 0 or fst_off >= source.size():
        return False
    return True


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

    File offsets are word-based (Wii convention): ``node_offset << 2`` gives
    the byte offset into the decrypted partition. Directory nesting uses the
    standard FST traversal (mirrors gc-fst): a directory's children are the
    contiguous nodes [self+1, next), recursed in order.
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
        base = i * _NODE_SIZE
        node = fst[base : base + _NODE_SIZE]
        name_off = int.from_bytes(node[1:4], "big")
        f1 = struct.unpack(">I", node[4:8])[0]
        f2 = struct.unpack(">I", node[8:12])[0]
        return node[0], _read_name(fst, strtab_base, name_off), f1, f2

    def _recurse(dir_index: int, next_index: int, prefix: str) -> None:
        i = dir_index + 1
        while i < next_index:
            ntype, name, f1, f2 = _node(i)
            path = f"{prefix}/{name}" if prefix else name
            if ntype == 0:  # file — offset is word-based
                file_off = f1 << _WORD_SHIFT
                if file_off + f2 > src_size:
                    raise ValueError(
                        f"file {name!r} range [{file_off}, {file_off + f2}) "
                        f"exceeds decrypted size {src_size}"
                    )
                entries.append(
                    FileEntry(path=path, kind="file", offset=file_off, size=f2)
                )
                i += 1
            elif ntype == 1:  # directory
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

    _recurse(0, node_count, "")
    return entries


def normalize_wii_fst(source) -> FileTree:
    """Parse a decrypted Wii DATA partition's FST into a FileTree.

    Accepts a path (str/Path) or a ByteSource over the decrypted DATA
    partition (the ``ByteView`` ``wii-partition`` returns, or its ``.source``).
    The returned FileTree reads file payloads lazily through that source.
    """
    src = source if isinstance(source, ByteSource) else FileSource(source)
    src_size = src.size()

    if src_size < _HEADER_MIN:
        raise ValueError("source too small to contain a Wii DATA partition header")

    fst_off = struct.unpack(">I", src.read_at(_FST_OFF_FIELD, 4))[0] << _WORD_SHIFT
    fst_size = struct.unpack(">I", src.read_at(_FST_SIZE_FIELD, 4))[0] << _WORD_SHIFT
    if fst_size == 0:
        raise ValueError("FST size is zero")
    if fst_off + fst_size > src_size:
        raise ValueError(
            f"FST range [{fst_off}, {fst_off + fst_size}) exceeds "
            f"decrypted size {src_size}"
        )
    fst = src.read_at(fst_off, fst_size)
    entries = _walk(fst, src_size)
    return FileTree(source=src, format="wii-fst", entries=tuple(entries))
