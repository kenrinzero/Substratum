#!/usr/bin/env python3
"""Stage the retail CISO anchor (fixtures/ciso/luigi).

Usage: python seedtools/stage_ciso_retail_anchor.py [<ciso-file>]

Defaults: fixtures/_local/Luigi's Mansion (USA, Canada).ciso (NKit 2's
wit-compatible CISO + appended recovery trailer).

Truth never derives from the normalizer under test (AGENTS.md § 3):
  - the expected manifest's file entries come from wit's independent
    `files-ll` listing (wit reads the container natively); directory
    entries are the file paths' ancestors, matching gc-fst's
    kind=dir/offset=0/size=0 convention;
  - reference bytes are wit `extract` output, flattened to reference/
    <entry path> so verify.py's check 4 finds them;
  - source.sha256 describes the DECODED VIEW and is computed here by this
    stager's own minimal slot placement (wit's `wit copy` reconstruction
    cannot serve as the view hash: it scrubs GC junk, so it differs from
    the view on the junk-bearing blocks 1 and 604 — characterized in the
    NORMALIZERS.md row). The retail test re-derives it through the
    normalizer and must match this pin.

The retail container and reference bytes stay gitignored; only the
metadata manifest commits.
"""

import hashlib
import posixpath
import shutil
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from stage_gc_fst import _wit_exe, entries_from_wit_listing, extract_reference, wit_version

from substratum.contract import FileEntry, FileTree, canonical_manifest, sha256_of

STAGER = "stage_ciso_retail_anchor v1"
ROOT = Path(__file__).resolve().parent.parent
DEFAULT = "fixtures/_local/Luigi's Mansion (USA, Canada).ciso"
BLOCK = 0x200000
TOTAL = 4_699_979_776
NBLOCKS = (TOTAL + BLOCK - 1) // BLOCK
CHUNK = 1 << 20


class _DecodedView:
    """Size-only stand-in: the manifest's source identity is the view."""

    def size(self) -> int:
        return TOTAL


def dir_entries(file_entries: list[FileEntry]) -> list[FileEntry]:
    dirs: set[str] = set()
    for e in file_entries:
        parent = posixpath.dirname(e.path)
        while parent:
            dirs.add(parent)
            parent = posixpath.dirname(parent)
    return [
        FileEntry(path=p, kind="dir", offset=0, size=0) for p in sorted(dirs)
    ]


def view_sha256(ciso: Path) -> str:
    """Hash the decoded view by placing slots per the container's own map —
    an independent minimal implementation, not the normalizer's."""
    with ciso.open("rb") as fh:
        head = fh.read(0x8000)
        if head[:4] != b"CISO":
            raise SystemExit("not a CISO container")
        (bs,) = struct.unpack_from("<I", head, 4)
        if bs != BLOCK:
            raise SystemExit(f"unexpected block size {bs:#x}")
        present = [i for i in range(NBLOCKS) if head[8 + i] == 1]
        rank = {block: slot for slot, block in enumerate(present)}

        h = hashlib.sha256()
        for block in range(NBLOCKS):
            want = min(BLOCK, TOTAL - block * BLOCK)
            slot = rank.get(block)
            pos = 0
            if slot is None:
                while pos < want:
                    h.update(bytes(min(CHUNK, want - pos)))
                    pos += CHUNK
            else:
                fh.seek(0x8000 + slot * BLOCK)
                while pos < want:
                    chunk = fh.read(min(CHUNK, want - pos))
                    h.update(chunk)
                    pos += len(chunk)
        return h.hexdigest()


def main() -> None:
    arg = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    ciso = (ROOT / arg) if not Path(arg).is_absolute() else Path(arg)
    if not ciso.exists():
        raise SystemExit(f"retail CISO not found: {ciso}")
    exe = _wit_exe()

    out = ROOT / "fixtures" / "ciso" / "luigi"
    out.mkdir(parents=True, exist_ok=True)

    files = entries_from_wit_listing(exe, ciso)
    if not files:
        raise SystemExit("no file entries parsed from wit files-ll — aborting")
    entries = sorted(files + dir_entries(files), key=lambda e: e.path)

    files_src = extract_reference(exe, ciso, out / "reference")
    ref_root = out / "reference"
    for e in files:
        src_file = files_src / e.path
        if not src_file.is_file():
            raise SystemExit(f"reference bytes missing for {e.path}")
        if src_file.stat().st_size != e.size:
            raise SystemExit(
                f"reference size mismatch for {e.path}: wit listing {e.size} "
                f"vs extracted {src_file.stat().st_size}"
            )
        dst_file = ref_root / e.path
        dst_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src_file, dst_file)
    shutil.rmtree(ref_root / "extract")

    vsha = view_sha256(ciso)
    tools = {"wit": wit_version(exe), "generator": STAGER}
    tree = FileTree(source=_DecodedView(), format="ciso", entries=tuple(entries))
    manifest = canonical_manifest(tree, ciso.name, vsha, tools)
    (out / "expected.manifest.json").write_bytes(manifest)

    print(
        f"staged {ciso.name} ({ciso.stat().st_size} bytes, "
        f"sha256 {sha256_of(ciso)})\n"
        f"{len(files)} files / {len(entries) - len(files)} dirs; "
        f"decoded view sha256 = {vsha}\ntools={tools}\n"
        f"manifest -> {out / 'expected.manifest.json'}\n"
        f"reference bytes (NOT committed) -> {ref_root}"
    )


if __name__ == "__main__":
    main()
