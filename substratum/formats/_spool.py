"""Lifecycle-managed temp-file spool source for container normalizers.

Normalizers that decode via an external tool (or a decompression spool)
write their output into a mkdtemp directory and serve it through this
ByteSource, which owns the directory's lifetime.  Extracted from the
DolphinTool plumbing when the `wbfs`/wit unit needed the same shape.
"""

from __future__ import annotations

import shutil
import weakref
from pathlib import Path

from substratum.contract import FileSource

__all__ = ["TempFileSource"]


class TempFileSource:
    """ByteSource over a temp file that owns its parent directory.

    Normal FileSource has no lifecycle hook, so this wrapper supplies
    explicit idempotent cleanup and a finalizer fallback.  The inner
    file's .path is exposed for completeness (composition does not need
    a sibling, but callers may inspect it).
    """

    def __init__(self, path: Path, tmp_dir: Path) -> None:
        self._inner = FileSource(path)
        self.path = path
        self._tmp_dir = tmp_dir
        self._finalizer = weakref.finalize(
            self, shutil.rmtree, tmp_dir, ignore_errors=True
        )

    def read_at(self, offset: int, size: int) -> bytes:
        return self._inner.read_at(offset, size)

    def size(self) -> int:
        return self._inner.size()

    def close(self) -> None:
        """Remove the owned extraction tree; safe to call more than once."""
        self._finalizer()

    def __enter__(self) -> TempFileSource:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
