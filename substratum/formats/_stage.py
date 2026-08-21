"""Shared "stage a ByteSource to a temp file" plumbing for tool wrappers.

`substratum/formats/{_dolphin.py, wbfs.py, nkit.py}` all decode a
container by shelling out to a foreign CLI that requires a filesystem
path. When the input is already a `FileSource` (i.e. on disk), the path
is reused as-is. Otherwise the bytes are streamed into a
`tempfile.NamedTemporaryFile(suffix=..., delete=False)` and the temp
path is handed to the tool; the caller's `finally` unlinks the staged
file alongside any other temp-dir cleanup. Failures during streaming
are cleaned up inside the helper before re-raising.

The 1 MiB streaming chunk is the shared house constant (the same
`min(1 << 20, ...)` idiom the prior audits recorded for the keyed
layers and the gate's fidelity chunk).

Runtime is stdlib-only per DESIGN.md § 4.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from substratum.contract import ByteSource, FileSource

__all__ = ["stage_to_tempfile"]


def stage_to_tempfile(source, *, suffix: str) -> tuple[Path, bool]:
    """Resolve `source` (path or ByteSource) to a filesystem path.

    Returns `(path, staged)`:

    - If `source` already names a file on disk — a path, a `FileSource`,
      or any `.path`-bearing ByteSource — returns that path with
      `staged=False`. No temp file is created; the caller does NOT own
      the path's lifetime.
    - Otherwise, streams `source` into a temp file and returns the
      temp path with `staged=True`. The caller owns the temp file's
      lifetime and is expected to unlink it on success; the helper
      unlinks it on any failure during streaming.

    The `.path` test is duck-typed, matching
    `ps1_bincue._resolve_pair` — the other place in the tree that asks
    "can I get a filesystem path out of this source?". It matters: a
    `_spool.TempFileSource` (what every chd / rvz / gcz / wbfs / nkit
    decode returns) wraps a `FileSource` rather than subclassing it, so
    an `isinstance` test would miss the path that is right there and
    copy a multi-gigabyte decoded image for nothing.

    The streaming chunk is 1 MiB (matches the gate's fidelity chunk
    and the keyed layers' streaming).
    """
    src = source if isinstance(source, ByteSource) else FileSource(source)
    on_disk = getattr(src, "path", None)
    if on_disk is not None:
        return Path(on_disk), False

    tmp_in = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    try:
        total = src.size()
        pos = 0
        while pos < total:
            chunk = src.read_at(pos, min(1 << 20, total - pos))
            tmp_in.write(chunk)
            pos += len(chunk)
        tmp_in.flush()
        tmp_in.close()
        return Path(tmp_in.name), True
    except BaseException:
        tmp_in.close()
        Path(tmp_in.name).unlink(missing_ok=True)
        raise
