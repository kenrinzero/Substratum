#!/usr/bin/env python3
"""Stage The Munchables DATA partition as a wii-fst fixture.

Usage:
    uv run python seedtools/stage_wii_fst_retail_anchor.py [<wii-iso>]

Builds the expected manifest from **wit's `files-ll` listing** (parsed
independently of substratum's own parser) and extracts reference bytes with
`wit extract`. Both are the independence-critical artifacts: truth never
derives from the normalizer under test (AGENTS.md §3). The retail ISO and
the common key are gitignored; decrypted reference bytes are NOT committed
(extracted fresh by this tool into fixtures/wii_fst/munchables/reference/).

The wii-fst normalizer composes wii-disc → wii-partition → FST walk. This
stager treats wit as the sole independent oracle for the decrypted FST
tree: wit decrypts the partition and reports the user-data file offsets/
sizes (already in byte form — wit resolves the Wii word-offset convention
itself). wit's `DATA/files/` subtree is the FST user-data filesystem; the
virtual `sys/` and root script entries are excluded (not FST records).

Requires:
    - fixtures/_local/The Munchables (USA).iso
    - tools/wit/wit.exe  (vendored via seedtools/vendor_tools.py wit)
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from seedtools import vendor_tools  # noqa: E402
from substratum.contract import (  # noqa: E402
    FileEntry,
    FileSource,
    FileTree,
    canonical_manifest,
    sha256_of,
)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ISO = ROOT / "fixtures" / "_local" / "The Munchables (USA).iso"
OUTPUT = ROOT / "fixtures" / "wii_fst" / "munchables"
STAGER = "stage_wii_fst_retail_anchor v1"
TOOL_TIMEOUT_SECONDS = 600

# Only the DATA partition carries the game filesystem; wit prefixes it "DATA/".
_PARTITION_PREFIX = "DATA/files/"

EXPECTED_ISO_SHA256 = (
    "64c012f35d0c8b97e34c13e47060550b36d89fc36bed2691661cfdf108671cbb"
)

# wit files-ll row shapes (same as gc_fst's stager):
#   9b0f0000+ 1dfb000  31436800  DATA/files/d01.dat
#       -         - N=53       DATA/files/        <- directory line
_FILE_ROW = re.compile(r"^\s*([0-9a-fA-F]+)\+\s+([0-9a-fA-F]+)\s+(\d+)\s+(.+)$")
_DIR_ROW = re.compile(r"^\s*-\s+-\s+N=(\d+)\s+(.+)/\s*$")


def _run_text(command: list[str]) -> str:
    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=TOOL_TIMEOUT_SECONDS,
    )
    if process.returncode != 0:
        raise SystemExit(
            f"tool failed with exit {process.returncode}: {command[0]}\n"
            f"{process.stdout[-500:]}\n{process.stderr[-500:]}"
        )
    return process.stdout + process.stderr


def _check_wit() -> str:
    wit = ROOT / "tools" / "wit" / "wit.exe"
    if not wit.is_file():
        raise SystemExit(
            "pinned wit is absent; run "
            "`uv run python seedtools/vendor_tools.py wit`"
        )
    vendor_tools.check_pin(wit, vendor_tools.WIT_EXE_SHA256, "wit exe")
    output = _run_text([str(wit), "version"])
    first = output.strip().splitlines()[0]
    if first != vendor_tools.WIT_BANNER:
        raise SystemExit("wit version banner drift")
    return first.split(":", 1)[1].strip()


def _entries_from_wit(wit: Path, iso: Path) -> list[FileEntry]:
    """Parse wit files-ll into FileEntries — the independent reader.

    Takes only DATA partition FST user-data files/dirs (wit's `DATA/files/`
    subtree), normalizing to bare relative posix paths. Virtual `sys/`,
    `disc/`, root scripts, cert/h3/ticket/tmd are excluded — not FST records.
    wit reports file offsets in byte form (it resolves the Wii word-offset
    convention itself), so these are the byte offsets the normalizer must
    agree on.
    """
    output = _run_text([str(wit), "files-ll", str(iso)])
    entries: list[FileEntry] = []
    in_data = False
    for line in output.splitlines():
        # Only parse the DATA partition block (skip UPDATE).
        if line.strip().endswith("DATA/"):
            in_data = True
            continue
        if line.strip().endswith("UPDATE/"):
            in_data = False
            continue
        if not in_data:
            continue
        # Directory row.
        dm = _DIR_ROW.match(line)
        if dm:
            path = dm.group(2)
            if not path.startswith(_PARTITION_PREFIX):
                continue
            name = path[len(_PARTITION_PREFIX):]
            if name:
                entries.append(FileEntry(path=name, kind="dir", offset=0, size=0))
            continue
        # File row.
        fm = _FILE_ROW.match(line)
        if not fm:
            continue
        off_hex, _size_hex, size_dec, path = fm.groups()
        path = path.strip()
        if not path.startswith(_PARTITION_PREFIX):
            continue
        name = path[len(_PARTITION_PREFIX):]
        if not name:
            continue
        entries.append(
            FileEntry(
                path=name, kind="file", offset=int(off_hex, 16), size=int(size_dec)
            )
        )
    entries.sort(key=lambda e: e.path)
    return entries


def _extract_reference(wit: Path, iso: Path, entries: list[FileEntry]) -> Path:
    """Extract DATA/files via wit into the gitignored reference dir, flattened
    to match entry paths so verify.py's check 4 finds bytes at
    ``reference_dir / entry.path``."""
    reference = OUTPUT / "reference"
    if reference.exists():
        shutil.rmtree(reference)
    reference.mkdir(parents=True)
    with tempfile.TemporaryDirectory(
        prefix="wii-fst-reference-", dir=OUTPUT
    ) as temp:
        dest = Path(temp) / "extract"
        _run_text([str(wit), "extract", str(iso), "-d", str(dest)])
        files_src = dest / "DATA" / "files"
        if not files_src.is_dir():
            raise SystemExit("wit extraction produced no DATA/files/ directory")
        for e in entries:
            if e.kind != "file":
                continue
            src_file = files_src / e.path
            if not src_file.is_file():
                raise SystemExit(f"reference bytes missing for {e.path}")
            if src_file.stat().st_size != e.size:
                raise SystemExit(
                    f"reference size mismatch for {e.path}: wit listing "
                    f"{e.size} vs extracted {src_file.stat().st_size}"
                )
            dst_file = reference / e.path
            dst_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src_file, dst_file)
    return reference


def main() -> None:
    if len(sys.argv) > 2:
        raise SystemExit(__doc__)
    iso = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else DEFAULT_ISO
    if not iso.is_file():
        raise SystemExit(f"Wii ISO not found: {iso}")
    iso_hash = sha256_of(iso)
    if iso_hash != EXPECTED_ISO_SHA256:
        raise SystemExit(f"ISO sha256 drift: {iso_hash} != validated anchor")

    wit_version = _check_wit()
    entries = _entries_from_wit(ROOT / "tools" / "wit" / "wit.exe", iso)
    files = [e for e in entries if e.kind == "file"]
    if not files:
        raise SystemExit("no file entries parsed from wit files-ll — aborting")

    OUTPUT.mkdir(parents=True, exist_ok=True)
    reference = _extract_reference(
        ROOT / "tools" / "wit" / "wit.exe", iso, entries
    )

    # The normalizer's FileTree.source is the decrypted DATA partition ByteView
    # (from wii-partition), so canonical_manifest records that source's size —
    # the decrypted payload size = cluster_count * 0x7C00. We derive the cluster
    # count independently from the partition's declared data-region size (the
    # header field at partition_offset+0x2BC, word-shifted), NOT from the
    # normalizer under test. The source NAME/sha256 stay the ISO (the
    # composition root the operator supplies).
    import struct  # noqa: E402
    from substratum.formats.wii_disc import normalize_wii_disc  # noqa: E402

    disc_tree = normalize_wii_disc(FileSource(iso))
    data_entry = next(
        e for e in disc_tree.entries if e.path == "partition-data.bin"
    )
    # Read the partition's declared data size from its header (0x2BC, word-shifted),
    # the same field wii-partition's _parse_partition_data_region reads.
    part_header = FileSource(iso).read_at(data_entry.offset, 0x2C0)
    data_size_words = struct.unpack_from(">I", part_header, 0x2BC)[0]
    data_size = data_size_words << 2
    _CLUSTER_SIZE = 0x8000
    _PAYLOAD_SIZE = 0x7C00
    decrypted_size = (data_size // _CLUSTER_SIZE) * _PAYLOAD_SIZE

    class _SizedSource:
        """Minimal ByteSource stand-in: reports the decrypted partition size
        so canonical_manifest emits the size the normalizer will agree on.
        Reads are unused (only size() is called for manifest authoring)."""

        def __init__(self, size: int) -> None:
            self._size = size

        def size(self) -> int:
            return self._size

        def read_at(self, offset: int, size: int) -> bytes:  # pragma: no cover
            raise NotImplementedError

    tools = {"wit": wit_version, "generator": STAGER}
    tree = FileTree(
        source=_SizedSource(decrypted_size),
        format="wii-fst",
        entries=tuple(entries),
    )
    manifest = canonical_manifest(tree, iso.name, iso_hash, tools)
    (OUTPUT / "expected.manifest.json").write_bytes(manifest)

    nd = sum(1 for e in entries if e.kind == "dir")
    print(
        f"staged {iso.name} DATA partition FST:\n"
        f"  {len(files)} files, {nd} dirs\n"
        f"  manifest -> {OUTPUT / 'expected.manifest.json'}\n"
        f"  reference bytes (gitignored) -> {reference}"
    )


if __name__ == "__main__":
    main()
