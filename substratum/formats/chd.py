"""CHD container normalizer (S3; NORMALIZERS.md row `chd`).

Returns exactly ONE layer — a ByteView of the decompressed disc.
Never recurses into inner filesystems (caller composes, DESIGN.md §1).

Decompression delegates to chdman, dispatched by the CHD's metadata tag:
DVD-tagged images use `extractdvd`, everything else `extractcd`. The
output .bin is the decompressed disc image. Source checkouts carry
chdman 0.288 (mame0288), while installed packages may select an
executable explicitly or discover one on PATH.

Runtime is stdlib-only per DESIGN.md § 4.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from substratum.contract import ByteSource, ByteView
from substratum.formats._spool import TempFileSource as _TempFileSource
from substratum.formats._stage import stage_to_tempfile

# `_TempFileSource` is the shared `_spool.TempFileSource` under this unit's
# historical private name: the extracted .bin lives in a mkdtemp directory the
# source owns, and its `.path` is what lets a composed `ps1-bincue` find the
# sibling .cue that `chdman extractcd` wrote beside it. Kept as an alias
# rather than a re-import so `chd_module._TempFileSource` stays a test surface
# (same shape as `rvz.py`).
__all__ = ["sniff", "normalize_chd"]

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


def _chd_tag(chd_path: Path) -> str | None:
    """Return the CHD metadata tag, if the tool exposes one.

    Malformed or unsupported CHDs may fail the metadata query; in that case,
    fall back to the safe CD extraction path instead of failing early.
    """
    try:
        info = subprocess.run(
            [str(_chdman_exe()), "info", "-i", str(chd_path)],
            capture_output=True,
            text=True,
            check=True,
            timeout=_CHDMAN_TIMEOUT_SECONDS,
        )
    except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired):
        return None
    for line in info.stdout.splitlines():
        if "Metadata:" not in line:
            continue
        match = re.search(r"Tag='([^']*)'", line)
        if match:
            return match.group(1)
    return None


def _chd_extract_command(chd_path: Path, tmp_dir: Path) -> tuple[list[str], Path]:
    """Dispatch CHD extraction by media tag and return the resulting binary path."""
    tag = _chd_tag(chd_path)
    if tag is not None and tag.strip() == "DVD":
        data_file = tmp_dir / "extracted.bin"
        return (
            [
                str(_chdman_exe()),
                "extractdvd",
                "-i",
                str(chd_path),
                "-o",
                str(data_file),
            ],
            data_file,
        )

    cue_file = tmp_dir / "extracted.cue"
    data_file = cue_file.with_suffix(".bin")
    return (
        [
            str(_chdman_exe()),
            "extractcd",
            "-i",
            str(chd_path),
            "-o",
            str(cue_file),
        ],
        data_file,
    )


def normalize_chd(source) -> ByteView:
    """Decompress a CHD to a ByteView of the raw disc image.

    Accepts a path (str/Path) or a ByteSource.  When given a ByteSource
    that is not already a file, the bytes are staged to a temp file
    because chdman requires a filesystem path.
    """
    # Resolve `source` to a filesystem path; stage to a temp file if it
    # isn't already one.  See `_stage.py` for the streaming + cleanup
    # contract; the caller's `finally` unlinks the staged file alongside
    # the temp-dir lifecycle.
    chd_path, staged = stage_to_tempfile(source, suffix=".chd")

    tmp_dir = Path(tempfile.mkdtemp(prefix="substratum-chd-"))

    try:
        command, data_file = _chd_extract_command(chd_path, tmp_dir)
        subprocess.run(
            command,
            capture_output=True,
            check=True,
            timeout=_CHDMAN_TIMEOUT_SECONDS,
        )
        if not data_file.exists():
            raise RuntimeError(f"chdman did not produce {data_file}")
        return ByteView(source=_TempFileSource(data_file, tmp_dir), format="chd")
    except BaseException:
        # Clean up temp dir on failure
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
    finally:
        # If we staged a temp CHD, clean it up
        if staged:
            chd_path.unlink(missing_ok=True)
