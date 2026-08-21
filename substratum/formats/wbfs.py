"""WBFS container normalizer (NORMALIZERS.md row `wbfs`).

Returns exactly ONE layer — a ByteView of the reconstructed disc image.
Never recurses into inner filesystems (caller composes, DESIGN.md §1).

Decompression delegates to wit (`wit copy`), the reference implementation
for the WBFS scrubbed container.  wit rebuilds the canonical full-size
Wii image, zero-filling scrubbed clusters — original junk bytes are
unrecoverable from a WBFS by design, and DolphinTool is NOT usable as a
second party for this format (its convert output on WBFS is mangled;
see the NORMALIZERS.md row).  The container differential is the
spec-derived pure-Python LUT decoder in tests/test_wbfs.py (libwbfs
layout).  The spool source lives in `substratum/formats/_spool.py`.

Runtime is stdlib-only per DESIGN.md § 4.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from substratum.contract import ByteSource, ByteView, FileSource
from substratum.formats._spool import TempFileSource

__all__ = ["sniff", "normalize_wbfs"]

_TIMEOUT_SECONDS = 300

_WIT_REL = Path("tools") / "wit" / "wit.exe"
WIT_ENV = "SUBSTRATUM_WIT"


def _repo_wit_candidate() -> Path:
    root = Path(__file__).resolve().parent.parent.parent
    return root / _WIT_REL


def wit_exe() -> Path:
    """Resolve wit for wheels and source checkouts in explicit order."""
    override = os.environ.get(WIT_ENV)
    if override is not None:
        if not override.strip():
            raise FileNotFoundError(f"{WIT_ENV} is set but empty")
        exe = Path(override).expanduser()
        if exe.is_file():
            return exe
        raise FileNotFoundError(
            f"{WIT_ENV} points to a missing file: {exe}"
        )

    on_path = shutil.which("wit")
    if on_path is not None:
        return Path(on_path)

    repo_exe = _repo_wit_candidate()
    if repo_exe.is_file():
        return repo_exe

    raise FileNotFoundError(
        "wit not found; set SUBSTRATUM_WIT to wit.exe, install wit on PATH, "
        "or re-vendor a source checkout with seedtools/vendor_tools.py wit"
    )


def sniff(source: ByteSource) -> bool:
    """True when the source starts with the WBFS magic 'WBFS'."""
    if source.size() < 4:
        return False
    return source.read_at(0, 4) == b"WBFS"


def normalize_wbfs(source) -> ByteView:
    """Reconstruct a WBFS to a ByteView of the full-size disc image.

    Accepts a path (str/Path) or a ByteSource.  When given a ByteSource
    that is not already a file, the bytes are staged to a temp file
    because wit requires a filesystem path.
    """
    src = source if isinstance(source, ByteSource) else FileSource(source)

    # --- resolve a filesystem path for wit ---
    if isinstance(src, FileSource):
        wbfs_path = src.path
        staged = False
    else:
        tmp_in = tempfile.NamedTemporaryFile(suffix=".wbfs", delete=False)
        try:
            total = src.size()
            pos = 0
            while pos < total:
                chunk = src.read_at(pos, min(1 << 20, total - pos))
                tmp_in.write(chunk)
                pos += len(chunk)
            tmp_in.flush()
            wbfs_path = Path(tmp_in.name)
            tmp_in.close()
            staged = True
        except BaseException:
            tmp_in.close()
            Path(tmp_in.name).unlink(missing_ok=True)
            raise

    tmp_dir = Path(tempfile.mkdtemp(prefix="substratum-wbfs-"))

    try:
        data_file = tmp_dir / "extracted.iso"
        command = [str(wit_exe()), "copy", str(wbfs_path), str(data_file)]
        subprocess.run(
            command,
            capture_output=True,
            check=True,
            timeout=_TIMEOUT_SECONDS,
        )
        if not data_file.exists():
            raise RuntimeError(f"wit did not produce {data_file}")
        return ByteView(source=TempFileSource(data_file, tmp_dir), format="wbfs")
    except BaseException:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
    finally:
        if staged:
            wbfs_path.unlink(missing_ok=True)
