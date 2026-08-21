"""RVZ container normalizer (NORMALIZERS.md row `rvz`).

Returns exactly ONE layer — a ByteView of the decompressed disc image.
Never recurses into inner filesystems (caller composes, DESIGN.md §1).

Decompression delegates to DolphinTool (`dolphin-tool convert`), the
reference RVZ codec from the Dolphin emulator project. Source checkouts
carry Dolphin 2606a (dolphin-tool 2606a), while installed packages may
select an executable explicitly or discover one on PATH.

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

__all__ = ["sniff", "normalize_rvz"]


class _TempFileSource:
    """ByteSource over a temp file that owns its parent directory.

    The extracted ISO lives in a mkdtemp directory.  Normal FileSource
    has no lifecycle hook, so this wrapper supplies explicit idempotent
    cleanup and a finalizer fallback.  The inner file's .path is exposed
    for completeness (composition does not need a sibling, but callers may
    inspect it).
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

    def __enter__(self) -> _TempFileSource:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


_DOLPHIN_REL = Path("tools") / "dolphin-tool" / "DolphinTool.exe"
_DOLPHIN_ENV = "SUBSTRATUM_DOLPHIN_TOOL"
_DOLPHIN_TIMEOUT_SECONDS = 300


def _repo_dolphin_candidate() -> Path:
    root = Path(__file__).resolve().parent.parent.parent
    return root / _DOLPHIN_REL


def _dolphin_tool_exe() -> Path:
    """Resolve dolphin-tool for wheels and source checkouts in explicit order."""
    override = os.environ.get(_DOLPHIN_ENV)
    if override is not None:
        if not override.strip():
            raise FileNotFoundError(f"{_DOLPHIN_ENV} is set but empty")
        exe = Path(override).expanduser()
        if exe.is_file():
            return exe
        raise FileNotFoundError(
            f"{_DOLPHIN_ENV} points to a missing file: {exe}"
        )

    on_path = shutil.which("dolphin-tool") or shutil.which("DolphinTool")
    if on_path is not None:
        return Path(on_path)

    repo_exe = _repo_dolphin_candidate()
    if repo_exe.is_file():
        return repo_exe

    raise FileNotFoundError(
        "dolphin-tool not found; set SUBSTRATUM_DOLPHIN_TOOL to DolphinTool.exe, "
        "install dolphin-tool on PATH, or re-vendor a source checkout with "
        "seedtools/vendor_tools.py dolphin-tool"
    )


def sniff(source: ByteSource) -> bool:
    """True when the source starts with the RVZ magic 'RVZ'."""
    if source.size() < 4:
        return False
    return source.read_at(0, 3) == b"RVZ"


def normalize_rvz(source) -> ByteView:
    """Decompress an RVZ to a ByteView of the raw disc image.

    Accepts a path (str/Path) or a ByteSource.  When given a ByteSource
    that is not already a file, the bytes are staged to a temp file
    because dolphin-tool requires a filesystem path.
    """
    src = source if isinstance(source, ByteSource) else FileSource(source)

    # --- resolve a filesystem path for dolphin-tool ---
    if isinstance(src, FileSource):
        rvz_path = src.path
    else:
        # stage a non-file ByteSource to a temp .rvz
        tmp_rvz = tempfile.NamedTemporaryFile(suffix=".rvz", delete=False)
        try:
            total = src.size()
            pos = 0
            while pos < total:
                chunk = src.read_at(pos, min(1 << 20, total - pos))
                tmp_rvz.write(chunk)
                pos += len(chunk)
            tmp_rvz.flush()
            rvz_path = Path(tmp_rvz.name)
            tmp_rvz.close()
        except BaseException:
            tmp_rvz.close()
            Path(tmp_rvz.name).unlink(missing_ok=True)
            raise

    tmp_dir = Path(tempfile.mkdtemp(prefix="substratum-rvz-"))

    try:
        data_file = tmp_dir / "extracted.iso"
        command = [
            str(_dolphin_tool_exe()),
            "convert",
            "-i",
            str(rvz_path),
            "-o",
            str(data_file),
            "--format",
            "iso",
        ]
        subprocess.run(
            command,
            capture_output=True,
            check=True,
            timeout=_DOLPHIN_TIMEOUT_SECONDS,
        )
        if not data_file.exists():
            raise RuntimeError(f"dolphin-tool did not produce {data_file}")
        return ByteView(source=_TempFileSource(data_file, tmp_dir), format="rvz")
    except BaseException:
        # Clean up temp dir on failure
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
    finally:
        # If we staged a temp RVZ, clean it up
        if not isinstance(src, FileSource):
            Path(rvz_path).unlink(missing_ok=True)
