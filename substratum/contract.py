"""The Substratum interface — FROZEN (DESIGN.md § 1). Four downstream
segments bind to this module; changes are program-wide contract changes."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Protocol, runtime_checkable

__all__ = [
    "ByteSource",
    "FileSource",
    "SliceSource",
    "ByteView",
    "FileEntry",
    "FileTree",
    "canonical_manifest",
    "sha256_of",
]


@runtime_checkable
class ByteSource(Protocol):
    """The one shared read primitive (DESIGN.md § 1)."""

    def read_at(self, offset: int, size: int) -> bytes: ...

    def size(self) -> int: ...


class FileSource:
    """A ByteSource over an on-disk dump file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._size = self.path.stat().st_size

    def read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self._size:
            raise ValueError(
                f"read [{offset}, {offset + size}) out of bounds (size {self._size})"
            )
        with self.path.open("rb") as fh:
            fh.seek(offset)
            return fh.read(size)

    def size(self) -> int:
        return self._size


class SliceSource:
    """A ByteSource over a byte range of another source — how FileTree
    entries are opened without materializing anything."""

    def __init__(self, parent: ByteSource, offset: int, size: int) -> None:
        if offset < 0 or size < 0 or offset + size > parent.size():
            raise ValueError("slice out of parent bounds")
        self._parent = parent
        self._offset = offset
        self._size = size

    def read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self._size:
            raise ValueError("read out of slice bounds")
        return self._parent.read_at(self._offset + offset, size)

    def size(self) -> int:
        return self._size


@dataclass(slots=True, frozen=True)
class ByteView:
    """A flat, seekable view (carts / raw images / decoded containers).
    Composition rule (DESIGN.md § 1): normalizers that decode a container
    return a ByteView; the CALLER re-normalizes it — never recurse."""

    source: ByteSource
    format: str


@dataclass(slots=True, frozen=True)
class FileEntry:
    """Eager metadata for one tree entry; bytes stay lazy."""

    path: str  # posix-style, relative, no leading slash
    kind: str  # "file" | "dir"
    offset: int  # byte range into the underlying source (0 for dirs)
    size: int


@dataclass(slots=True, frozen=True)
class FileTree:
    """An enumerable tree with seekable byte ranges into `source`."""

    source: ByteSource
    format: str
    entries: tuple[FileEntry, ...]

    def files(self) -> Iterator[FileEntry]:
        return (e for e in self.entries if e.kind == "file")

    def open(self, entry: FileEntry) -> SliceSource:
        return SliceSource(self.source, entry.offset, entry.size)

    def read(self, entry: FileEntry) -> bytes:
        return self.open(entry).read_at(0, entry.size)


def canonical_manifest(
    tree: FileTree, source_name: str, source_sha256: str, tool_versions: dict[str, str]
) -> bytes:
    """The downstream handoff / fixture-expected serialization
    (DESIGN.md § 2): sorted entries, sorted keys, ensure_ascii (JP
    filenames survive as escapes), trailing newline."""
    doc = {
        "format": tree.format,
        "source": {
            "name": source_name,
            "sha256": source_sha256,
            "size": tree.source.size(),
        },
        "tool_versions": tool_versions,
        "entries": [
            {"path": e.path, "kind": e.kind, "offset": e.offset, "size": e.size}
            for e in sorted(tree.entries, key=lambda e: e.path)
        ],
    }
    text = json.dumps(doc, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return (text + "\n").encode("ascii")


def sha256_of(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
