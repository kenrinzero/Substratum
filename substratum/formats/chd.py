"""CHD container normalizer (S3; NORMALIZERS.md row `chd`).

Returns exactly ONE layer — a ByteView of the decompressed disc.
Never recurses into inner filesystems (caller composes, DESIGN.md §1).

Decompression delegates to chdman via `extractcd`; the output .bin is
the original 2048-byte-sector ISO. Source checkouts carry chdman 0.288
(mame0288), while installed packages may select an executable explicitly
or discover one on PATH.

Runtime is stdlib-only per DESIGN.md § 4.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import weakref
from pathlib import Path

from substratum.contract import ByteSource, ByteView, FileSource

__all__ = ["sniff", "normalize_chd"]


class _TempFileSource:
    """ByteSource over a temp file that owns its parent directory.

    The extracted .bin lives in a mkdtemp directory.  Normal FileSource
    has no lifecycle hook, so this wrapper supplies explicit idempotent
    cleanup and a finalizer fallback.
    """

    def __init__(self, path: Path, tmp_dir: Path) -> None:
        self._inner = FileSource(path)
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

    def __enter__(self) -> _TempFileSource:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


_CHDMAN_REL = Path("tools") / "chdman" / "chdman.exe"
_CHDMAN_ENV = "SUBSTRATUM_CHDMAN"
_CHDMAN_TIMEOUT_SECONDS = 300


def _repo_chdman_candidate() -> Path:
    root = Path(__file__).resolve().parent.parent.parent
    return root / _CHDMAN_REL


def _chdman_exe() -> Path:
    """Resolve chdman for wheels and source checkouts in explicit order."""
    override = os.environ.get(_CHDMAN_ENV)
    if override is not None:
        if not override.strip():
            raise FileNotFoundError(f"{_CHDMAN_ENV} is set but empty")
        exe = Path(override).expanduser()
        if exe.is_file():
            return exe
        raise FileNotFoundError(
            f"{_CHDMAN_ENV} points to a missing file: {exe}"
        )

    on_path = shutil.which("chdman")
    if on_path is not None:
        return Path(on_path)

    repo_exe = _repo_chdman_candidate()
    if repo_exe.is_file():
        return repo_exe

    raise FileNotFoundError(
        "chdman not found; set SUBSTRATUM_CHDMAN to chdman.exe, "
        "install chdman on PATH, or re-vendor a source checkout with "
        "seedtools/vendor_tools.py chdman"
    )


def sniff(source: ByteSource) -> bool:
    """True when the source starts with the CHD magic 'MComprHD'."""
    if source.size() < 8:
        return False
    return source.read_at(0, 8) == b"MComprHD"


def normalize_chd(source) -> ByteView:
    """Decompress a CHD to a ByteView of the raw disc image.

    Accepts a path (str/Path) or a ByteSource.  When given a ByteSource
    that is not already a file, the bytes are staged to a temp file
    because chdman requires a filesystem path.
    """
    src = source if isinstance(source, ByteSource) else FileSource(source)

    # --- resolve a filesystem path for chdman ---
    if isinstance(src, FileSource):
        chd_path = src.path
    else:
        # stage a non-file ByteSource to a temp .chd
        tmp_chd = tempfile.NamedTemporaryFile(suffix=".chd", delete=False)
        try:
            total = src.size()
            pos = 0
            while pos < total:
                chunk = src.read_at(pos, min(1 << 20, total - pos))
                tmp_chd.write(chunk)
                pos += len(chunk)
            tmp_chd.flush()
            chd_path = Path(tmp_chd.name)
            tmp_chd.close()
        except BaseException:
            tmp_chd.close()
            Path(tmp_chd.name).unlink(missing_ok=True)
            raise

    # --- decompress with chdman extractcd ---
    tmp_dir = Path(tempfile.mkdtemp(prefix="substratum-chd-"))
    out_base = tmp_dir / "extracted"

    try:
        subprocess.run(
            [
                str(_chdman_exe()),
                "extractcd",
                "-i", str(chd_path),
                "-o", str(out_base),
            ],
            capture_output=True,
            check=True,
            timeout=_CHDMAN_TIMEOUT_SECONDS,
        )
        data_file = Path(str(out_base) + ".bin")
        if not data_file.exists():
            raise RuntimeError(f"chdman extractcd did not produce {data_file}")
        return ByteView(source=_TempFileSource(data_file, tmp_dir), format="chd")
    except BaseException:
        # Clean up temp dir on failure
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
    finally:
        # If we staged a temp CHD, clean it up
        if not isinstance(src, FileSource):
            Path(chd_path).unlink(missing_ok=True)
