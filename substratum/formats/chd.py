"""CHD container normalizer (S3; NORMALIZERS.md row `chd`).

Returns exactly ONE layer — a ByteView of the decompressed disc.
Never recurses into inner filesystems (caller composes, DESIGN.md §1).

Decompression delegates to vendored chdman 0.288 (mame0288) via
`extractcd`; the output .bin is the original 2048-byte-sector ISO.

Runtime is stdlib-only per DESIGN.md § 4.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from substratum.contract import ByteSource, ByteView, FileSource

__all__ = ["sniff", "normalize_chd"]


class _TempFileSource:
    """ByteSource over a temp file that owns its parent directory.

    The extracted .bin lives in a mkdtemp directory.  Normal FileSource
    has no lifecycle hook, so the directory would leak.  This wrapper
    delegates reads to a FileSource and removes the temp tree from
    __del__, so the caller needn't manage cleanup explicitly.
    """

    def __init__(self, path: Path, tmp_dir: Path) -> None:
        self._inner = FileSource(path)
        self._tmp_dir = tmp_dir

    def read_at(self, offset: int, size: int) -> bytes:
        return self._inner.read_at(offset, size)

    def size(self) -> int:
        return self._inner.size()

    def __del__(self) -> None:
        shutil.rmtree(self._tmp_dir, ignore_errors=True)

_CHDMAN_REL = Path("tools") / "chdman" / "chdman.exe"
_CHDMAN_TIMEOUT_SECONDS = 300


def _chdman_exe() -> Path:
    """Locate vendored chdman relative to the repo root."""
    root = Path(__file__).resolve().parent.parent.parent
    exe = root / _CHDMAN_REL
    if not exe.exists():
        raise FileNotFoundError(
            f"chdman not found at {exe}; re-vendor via seedtools/vendor_tools.py"
        )
    return exe


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
