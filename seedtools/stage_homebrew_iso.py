#!/usr/bin/env python3
"""Stage a homebrew ISO as an iso9660 fixture (S1; DESIGN.md § 5 tier 2).

Usage: python seedtools/stage_homebrew_iso.py <iso-file> <fixture-name>

Copies the ISO into fixtures/iso9660/<fixture-name>/, builds the expected
manifest from pycdlib's records (second reader), cross-checks the listing
against 7-Zip, and extracts reference bytes with 7-Zip — the same
two-independent-readers discipline as make_iso_fixture.py, for bytes a
third-party mastering tool authored (the symmetric-bug antidote).

The cross-check doubles as the acceptance filter: an ISO whose 7-Zip view
disagrees with its PVD view (Joliet/UDF-preferred images) aborts staging
and should be rejected or handled by a future unit, not munged into green.

Provenance (URL, upstream sha256, license evidence) is recorded by hand in
the fixture dir's PROVENANCE.md — this tool only prints the sha256.
"""

import shutil
import sys
from importlib.metadata import version as dist_version
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from make_iso_fixture import (
    entries_from_pycdlib,
    extract_reference,
    listing_from_7z,
    sevenzip_version,
)

from substratum.contract import FileSource, FileTree, canonical_manifest, sha256_of

STAGER = "stage_homebrew_iso v1"


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    src = Path(sys.argv[1])
    name = sys.argv[2]
    out = Path(__file__).resolve().parent.parent / "fixtures" / "iso9660" / name
    out.mkdir(parents=True, exist_ok=True)
    iso_path = out / f"{name}.iso"
    shutil.copyfile(src, iso_path)

    entries = entries_from_pycdlib(iso_path)
    listing = listing_from_7z(iso_path)
    ours = {e.path: (e.kind, e.size) for e in entries}
    if set(ours) != set(listing):
        raise SystemExit(
            "REJECTED - 7z/pycdlib listing mismatch (Joliet/UDF-preferred "
            f"image?): {sorted(set(ours) ^ set(listing))[:10]}"
        )
    for path, (kind, size) in ours.items():
        zkind, zsize = listing[path]
        if kind != zkind or (kind == "file" and size != zsize):
            raise SystemExit(f"REJECTED - 7z/pycdlib disagree on {path}: "
                             f"{kind},{size} vs {zkind},{zsize}")

    extract_reference(iso_path, out / "reference")
    for e in entries:
        if e.kind == "file":
            ref = out / "reference" / e.path
            if not ref.is_file() or ref.stat().st_size != e.size:
                raise SystemExit(f"reference bytes missing/short for {e.path}")

    tools = {"7z": sevenzip_version(), "pycdlib": dist_version("pycdlib"), "generator": STAGER}
    tree = FileTree(source=FileSource(iso_path), format="iso9660", entries=tuple(entries))
    manifest = canonical_manifest(tree, iso_path.name, sha256_of(iso_path), tools)
    (out / "expected.manifest.json").write_bytes(manifest)
    print(f"staged {iso_path} ({iso_path.stat().st_size} bytes, sha256 {sha256_of(iso_path)})\n"
          f"{sum(1 for e in entries if e.kind == 'file')} files / "
          f"{sum(1 for e in entries if e.kind == 'dir')} dirs, tools={tools}\n"
          f"now write {out / 'PROVENANCE.md'} (URL, upstream evidence, license)")


if __name__ == "__main__":
    main()
