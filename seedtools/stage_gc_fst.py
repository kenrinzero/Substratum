#!/usr/bin/env python3
"""Stage a GameCube ISO as a gc-fst fixture (S2; DESIGN.md § 5 tier 3 —
FIXTURE REQUEST retail drop).

Usage: python seedtools/stage_gc_fst.py [<iso-file>] [<fixture-name>]

Defaults: fixtures/_local/The Hulk (USA).iso  ->  fixtures/gc_fst/hulk/

Builds the expected manifest from **wit's `files-ll` listing** (the sole
differential tool — parsed independently of substratum's own parser), and
extracts reference bytes with `wit extract`. Both are the
independence-critical artifacts: truth never derives from the normalizer
under test (AGENTS.md § 3). The retail ISO is gitignored; only metadata
(paths, offsets, sizes) is committed. Reference bytes are NOT committed
(extracted fresh by this tool into fixtures/gc_fst/<name>/reference/).

wit publishes a *virtual* directory tree: `P-<GAMEID>/sys/` (fixed disc-
header regions: boot.bin, bi2.bin, apploader.img, main.dol, fst.bin) and
occasionally root-level setup scripts. The FST describes only the
user-data filesystem — wit's `P-<GAMEID>/files/` subtree. This stager
takes the `files/` entries only, dropping the `P-<GAMEID>/` prefix and
the `sys/` virtual view, mirroring how the normalizer parses the FST.
"""

import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from substratum.contract import FileEntry, FileSource, FileTree, canonical_manifest, sha256_of

_WIT_REL = Path("tools") / "wit" / "wit.exe"
STAGER = "stage_gc_fst v1"
TOOL_TIMEOUT_SECONDS = 300


def _wit_exe() -> Path:
    root = Path(__file__).resolve().parent.parent
    exe = root / _WIT_REL
    if not exe.exists():
        raise SystemExit(f"wit not found at {exe}; re-vendor via seedtools/vendor_tools.py")
    return exe


def wit_version(exe: Path) -> str:
    """First banner line, e.g. 'wit: Wiimms ISO Tool v3.05a r8638 cygwin64 ...'."""
    out = subprocess.run(
        [str(exe), "version"], capture_output=True, text=True, check=True,
        timeout=TOOL_TIMEOUT_SECONDS,
    )
    first = out.stdout.strip().splitlines()[0]
    # strip the leading "wit: " to leave "Wiimms ISO Tool v3.05a r8638 cygwin64 - ..."
    return first.split(":", 1)[1].strip() if first.lower().startswith("wit:") else first


# wit files-ll row example:
#   379b650+       18        24  P-GHKE/files/args.txt
#       -         - N=11       P-GHKE/files/        <- directory line (no offset)
# A file row: <hex_off>+ <hex_size> <dec_size> <path>
# A dir row :      -         - N=<count> <path>/  (trailing slash)
_FILE_ROW = re.compile(
    r"^\s*([0-9a-fA-F]+)\+\s+([0-9a-fA-F]+)\s+(\d+)\s+(.+)$"
)
_DIR_ROW = re.compile(r"^\s*-\s+-\s+N=(\d+)\s+(.+)/\s*$")


def entries_from_wit_listing(exe: Path, iso: Path) -> list[FileEntry]:
    """Parse wit files-ll into FileEntries — the independent reader.

    Takes only the real user-data files (wit's `.../files/<name>` paths),
    normalizing to bare relative posix names. Virtual `sys/` entries and
    any root-level scripts (offset 0, non-FST) are excluded: they are not
    FST records.
    """
    out = subprocess.run(
        [str(exe), "files-ll", str(iso)], capture_output=True, text=True, check=True,
        timeout=TOOL_TIMEOUT_SECONDS,
    )
    entries: list[FileEntry] = []
    for line in out.stdout.splitlines():
        m = _FILE_ROW.match(line)
        if not m:
            continue
        off_hex, _size_hex, size_dec, path = m.group(1), m.group(2), m.group(3), m.group(4)
        path = path.strip()
        # Keep only FST user-data files: wit nests them under <PREFIX>/files/
        if "/files/" not in path + "/":
            continue
        # strip everything up to and including the files/ segment
        name = path.split("/files/", 1)[1] if "/files/" in path else path
        if not name:
            continue
        entries.append(
            FileEntry(path=name, kind="file", offset=int(off_hex, 16), size=int(size_dec))
        )
    entries.sort(key=lambda e: e.path)
    return entries


def extract_reference(exe: Path, iso: Path, dest: Path) -> Path:
    """Run `wit extract` and return the path to the extracted P-<GAMEID>/files dir.

    wit refuses to extract into an existing directory, so we point it at a
    fresh subdirectory under dest and let it create the tree.
    """
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / "extract"  # wit creates this
    subprocess.run(
        [str(exe), "extract", str(iso), str(target)],
        capture_output=True,
        check=True,
        timeout=TOOL_TIMEOUT_SECONDS,
    )
    # locate the P-<GAMEID>/files directory (nested under extract/)
    pdir = next(target.glob("P-*/"), None)
    if pdir is None or not (pdir / "files").is_dir():
        raise SystemExit(f"wit extract produced no P-*/files/ under {target}")
    return pdir / "files"


def main() -> None:
    iso_arg = sys.argv[1] if len(sys.argv) > 1 else "fixtures/_local/The Hulk (USA).iso"
    name = sys.argv[2] if len(sys.argv) > 2 else "hulk"
    root = Path(__file__).resolve().parent.parent
    iso = (root / iso_arg) if not Path(iso_arg).is_absolute() else Path(iso_arg)
    if not iso.exists():
        raise SystemExit(f"ISO not found: {iso}")
    exe = _wit_exe()
    out = root / "fixtures" / "gc_fst" / name
    out.mkdir(parents=True, exist_ok=True)

    entries = entries_from_wit_listing(exe, iso)
    if not entries:
        raise SystemExit("no file entries parsed from wit files-ll — aborting")

    files_src = extract_reference(exe, iso, out / "reference")
    # Flatten the extracted P-<GAMEID>/files/<name> tree into reference/<name>
    # so verify.py's check 4 finds bytes at `reference_dir / entry.path`
    # (mirrors the iso9660 reference layout). Then drop the wit scaffolding.
    ref_root = out / "reference"
    for e in entries:
        src_file = files_src / e.path
        dst_file = ref_root / e.path
        if not src_file.is_file():
            raise SystemExit(f"reference bytes missing for {e.path}")
        if src_file.stat().st_size != e.size:
            raise SystemExit(
                f"reference size mismatch for {e.path}: wit listing {e.size} "
                f"vs extracted {src_file.stat().st_size}"
            )
        dst_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src_file, dst_file)
    shutil.rmtree(ref_root / "extract")

    tools = {"wit": wit_version(exe), "generator": STAGER}
    tree = FileTree(source=FileSource(iso), format="gc-fst", entries=tuple(entries))
    manifest = canonical_manifest(tree, iso.name, sha256_of(iso), tools)
    (out / "expected.manifest.json").write_bytes(manifest)

    nf = sum(1 for e in entries if e.kind == "file")
    print(
        f"staged {iso.name} ({iso.stat().st_size} bytes, sha256 {sha256_of(iso)})\n"
        f"{nf} files, tools={tools}\n"
        f"manifest -> {out / 'expected.manifest.json'}\n"
        f"reference bytes (NOT committed) -> {ref_root}"
    )


if __name__ == "__main__":
    main()
