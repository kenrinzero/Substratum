"""NKit container normalizer (NORMALIZERS.md row `nkit`).

Returns exactly ONE layer — a ByteView of the RECOVERED full-size disc
image.  Never recurses into inner filesystems (caller composes,
DESIGN.md §1).

Scope: GC `.nkit.iso` — a compacted GameCube image carrying the ``NKIT``
signature block at 0x200 behind a real GC disc header (the compacted
filesystem is directly walkable by `gc-fst`; the normalizer instead
returns NKit's recovered original: junk regenerated, original FST order
restored).  Wii NKit (RVT-H-ish `nkit.iso`/`.nkit.gcz`) has no sample and
stays out of scope; a `.nkit.gcz` wraps the compacted image in a
Dolphin-GCZ block stream and sniffs/decodes via `gcz` to the compacted
image (file-level correct via `gc-fst`).

Recovery delegates to NKit 1.4 (Nanook) — the last public NKit release;
NKit 2 is Discord-distributed with no public source (recorded).  The
tool writes into `<exe-dir>/Processed/` with no output flag, so each
call runs an isolated ~1 MB copy of the vendored tool inside its temp
spool (race-free, nothing shared).  The differential (round-trip from
independent retail bytes) lives in tests/test_nkit.py.

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

__all__ = ["sniff", "normalize_nkit"]

_TIMEOUT_SECONDS = 300

_NKIT_REL = Path("tools") / "nkit"
NKIT_ENV = "SUBSTRATUM_NKIT"

_GC_MAGIC = bytes.fromhex("c2339f3d")


def _repo_nkit_candidate() -> Path:
    root = Path(__file__).resolve().parent.parent.parent
    return root / _NKIT_REL


def nkit_tool_dir() -> Path:
    """Resolve the NKit 1.4 tool directory (holding ConvertToISO.exe)."""
    override = os.environ.get(NKIT_ENV)
    if override is not None:
        if not override.strip():
            raise FileNotFoundError(f"{NKIT_ENV} is set but empty")
        tool = Path(override).expanduser()
        if (tool / "ConvertToISO.exe").is_file():
            return tool
        raise FileNotFoundError(
            f"{NKIT_ENV} does not point at an NKit tool dir (no ConvertToISO.exe): {tool}"
        )

    repo_tool = _repo_nkit_candidate()
    if (repo_tool / "ConvertToISO.exe").is_file():
        return repo_tool

    raise FileNotFoundError(
        "NKit tool not found; set SUBSTRATUM_NKIT to the vendored tool directory "
        "or re-vendor a source checkout with seedtools/vendor_tools.py nkit"
    )


def sniff(source: ByteSource) -> bool:
    """True for a GC NKit: 'NKIT' at 0x200 corroborated by the GC disc magic.

    The signature is 4 bytes inside a normally-zero boot region, so the
    disc magic at 0x1C must agree (house rule: <=4-byte signatures need
    corroboration; a plain GC ISO carries zeros at 0x200 and a bare
    'NKIT' block without the disc magic must not be claimed).
    """
    if source.size() < 0x204:
        return False
    if source.read_at(0x200, 4) != b"NKIT":
        return False
    return source.read_at(0x1C, 4) == _GC_MAGIC


def normalize_nkit(source) -> ByteView:
    """Recover a GC NKit to a ByteView of the full-size original image.

    Accepts a path (str/Path) or a ByteSource.  When given a ByteSource
    that is not already a file, the bytes are staged to a temp file
    because the tool requires a filesystem path.
    """
    src = source if isinstance(source, ByteSource) else FileSource(source)

    # --- resolve a filesystem path for the tool ---
    if isinstance(src, FileSource):
        nkit_path = src.path
        staged = False
    else:
        tmp_in = tempfile.NamedTemporaryFile(suffix=".nkit.iso", delete=False)
        try:
            total = src.size()
            pos = 0
            while pos < total:
                chunk = src.read_at(pos, min(1 << 20, total - pos))
                tmp_in.write(chunk)
                pos += len(chunk)
            tmp_in.flush()
            nkit_path = Path(tmp_in.name)
            tmp_in.close()
            staged = True
        except BaseException:
            tmp_in.close()
            Path(tmp_in.name).unlink(missing_ok=True)
            raise

    tmp_dir = Path(tempfile.mkdtemp(prefix="substratum-nkit-"))

    try:
        # isolated per-call copy: the tool hardcodes <exe-dir>/Processed
        tool = tmp_dir / "tool"
        shutil.copytree(nkit_tool_dir(), tool)
        # NOTE: no check=True — the tool signals "CRC not in the (empty)
        # Redump/Custom dat" via a nonzero exit code even on a fully
        # verified conversion, so the produced image is the success
        # criterion, not the exit status.
        proc = subprocess.run(
            [str(tool / "ConvertToISO.exe"), str(nkit_path)],
            capture_output=True,
            timeout=_TIMEOUT_SECONDS,
        )
        outs = [
            p
            for p in (tool / "Processed").rglob("*.iso")
            if not p.name.endswith(".nkit.iso")
        ]
        if len(outs) != 1:
            detail = proc.stdout.decode("utf-8", "replace")[-400:]
            raise RuntimeError(
                f"ConvertToISO produced {len(outs)} images (expected 1) "
                f"under {tool / 'Processed'}; exit {proc.returncode}; tail: {detail!r}"
            )
        return ByteView(source=TempFileSource(outs[0], tmp_dir), format="nkit")
    except BaseException:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
    finally:
        if staged:
            nkit_path.unlink(missing_ok=True)
