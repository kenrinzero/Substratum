"""TOYFS normalizers for harness self-tests (NOT a real format).

`normalize_toy` is the correct implementation. The two mutants embody the
plan's red-team cases: `mutant_metadata` mis-parses offsets (caught by the
manifest check), and `mutant_slicer` — the load-bearing one — emits
PERFECT metadata but reads every byte range shifted by one, staying fully
self-consistent and in-bounds (the fixture carries one pad byte). Checks
1-3 pass it; only differential byte-range fidelity kills it (DESIGN § 3).
"""

from __future__ import annotations

import struct

from substratum.contract import FileEntry, FileSource, FileTree


def _parse(source) -> list[FileEntry]:
    if source.read_at(0, 4) != b"TOYF":
        raise ValueError("bad TOYFS magic")
    (count,) = struct.unpack("<I", source.read_at(4, 4))
    entries = []
    for i in range(count):
        rec = source.read_at(8 + i * 24, 24)
        name = rec[:16].rstrip(b"\x00").decode("ascii")
        offset, size = struct.unpack("<II", rec[16:24])
        entries.append(FileEntry(path=name, kind="file", offset=offset, size=size))
    return entries


def normalize_toy(path) -> FileTree:
    src = FileSource(path)
    return FileTree(source=src, format="toyfs", entries=tuple(_parse(src)))


def normalize_toy_mutant_metadata(path) -> FileTree:
    """Off-by-one in the PARSED offsets — wrong metadata, still walkable."""
    src = FileSource(path)
    entries = tuple(
        FileEntry(e.path, e.kind, e.offset + 1, e.size) for e in _parse(src)
    )
    return FileTree(source=src, format="toyfs", entries=entries)


class _ShiftedSource:
    """Reads shifted by one byte while LYING consistently about size —
    metadata stays perfect, every sliced byte is wrong."""

    def __init__(self, inner) -> None:
        self._inner = inner

    def read_at(self, offset: int, size: int) -> bytes:
        return self._inner.read_at(offset + 1, size)

    def size(self) -> int:
        return self._inner.size()


def normalize_toy_mutant_slicer(path) -> FileTree:
    src = FileSource(path)
    entries = tuple(_parse(src))
    return FileTree(source=_ShiftedSource(src), format="toyfs", entries=entries)
