"""Shared DolphinTool plumbing for the Dolphin container normalizers.

The `rvz` and `gcz` units both decode by asking DolphinTool
(`dolphin-tool convert --format iso`) to write the raw disc image into a
spool directory, then serving the result as a ByteView over a
lifecycle-managed temp source.  Source checkouts carry Dolphin 2606a
(dolphin-tool 2606a), while installed packages may select an executable
explicitly or discover one on PATH.

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

__all__ = ["DOLPHIN_ENV", "TempFileSource", "convert_disc_to_iso", "dolphin_tool_exe"]

_TIMEOUT_SECONDS = 300

_DOLPHIN_REL = Path("tools") / "dolphin-tool" / "DolphinTool.exe"
DOLPHIN_ENV = "SUBSTRATUM_DOLPHIN_TOOL"


def _repo_dolphin_candidate() -> Path:
    root = Path(__file__).resolve().parent.parent.parent
    return root / _DOLPHIN_REL


def dolphin_tool_exe() -> Path:
    """Resolve dolphin-tool for wheels and source checkouts in explicit order."""
    override = os.environ.get(DOLPHIN_ENV)
    if override is not None:
        if not override.strip():
            raise FileNotFoundError(f"{DOLPHIN_ENV} is set but empty")
        exe = Path(override).expanduser()
        if exe.is_file():
            return exe
        raise FileNotFoundError(
            f"{DOLPHIN_ENV} points to a missing file: {exe}"
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


def convert_disc_to_iso(source, *, format_tag: str) -> ByteView:
    """Decode a Dolphin disc container (rvz/gcz) to a ByteView of the raw ISO.

    Accepts a path (str/Path) or a ByteSource.  When given a ByteSource
    that is not already a file, the bytes are staged to a temp file
    because dolphin-tool requires a filesystem path.
    """
    src = source if isinstance(source, ByteSource) else FileSource(source)

    # --- resolve a filesystem path for dolphin-tool ---
    if isinstance(src, FileSource):
        container_path = src.path
        staged = False
    else:
        # stage a non-file ByteSource to a temp container file
        tmp_in = tempfile.NamedTemporaryFile(suffix=f".{format_tag}", delete=False)
        try:
            total = src.size()
            pos = 0
            while pos < total:
                chunk = src.read_at(pos, min(1 << 20, total - pos))
                tmp_in.write(chunk)
                pos += len(chunk)
            tmp_in.flush()
            container_path = Path(tmp_in.name)
            tmp_in.close()
            staged = True
        except BaseException:
            tmp_in.close()
            Path(tmp_in.name).unlink(missing_ok=True)
            raise

    tmp_dir = Path(tempfile.mkdtemp(prefix=f"substratum-{format_tag}-"))

    try:
        data_file = tmp_dir / "extracted.iso"
        command = [
            str(dolphin_tool_exe()),
            "convert",
            "-i",
            str(container_path),
            "-o",
            str(data_file),
            "--format",
            "iso",
        ]
        subprocess.run(
            command,
            capture_output=True,
            check=True,
            timeout=_TIMEOUT_SECONDS,
        )
        if not data_file.exists():
            raise RuntimeError(f"dolphin-tool did not produce {data_file}")
        return ByteView(source=TempFileSource(data_file, tmp_dir), format=format_tag)
    except BaseException:
        # Clean up temp dir on failure
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
    finally:
        # If we staged a temp container, clean it up
        if staged:
            container_path.unlink(missing_ok=True)
