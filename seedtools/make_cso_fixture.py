#!/usr/bin/env python3
"""Author the synthetic CSO/CISO fixture (NORMALIZERS.md row `cso`).

Reuses the committed iso9660 synthetic fixture as the inner truth — its
sha256-chain blob payloads are incompressible, so maxcso emits a MIX of
compressed and stored-raw blocks, exercising the CISO top-bit path:

  1. compress fixtures/iso9660/synthetic/synthetic.iso -> game.cso (maxcso).
  2. structural anchor: `maxcso --decompress game.cso` must reproduce the
     source ISO byte-exact — a third-party confirmation the .cso is a valid
     CISO, not a fixture only substratum's parser happens to accept.
  3. expected manifest = the iso9660 tree of that ISO with format="cso";
     entries are authored from pycdlib's OWN records (the second reader,
     never substratum's parser). source.sha256/size describe the
     DECOMPRESSED inner ISO (byte-identical to the source), source.name is
     the .cso — the same shape the chd unit uses.

Reference bytes are the iso9660 synthetic fixture's reference/ (the inner
disc is byte-identical), so nothing is duplicated. Only game.cso and
expected.manifest.json are written under fixtures/cso/synthetic/.
"""

import subprocess
import sys
from importlib.metadata import version as dist_version
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from make_iso_fixture import entries_from_pycdlib

from substratum.contract import FileSource, FileTree, canonical_manifest, sha256_of

GENERATOR = "make_cso_fixture v1"
ROOT = Path(__file__).resolve().parent.parent
MAXCSO = ROOT / "tools" / "maxcso" / "maxcso.exe"
ISO = ROOT / "fixtures" / "iso9660" / "synthetic" / "synthetic.iso"
MAXCSO_VERSION = "v1.13.0"


def maxcso_version() -> str:
    p = subprocess.run(
        [str(MAXCSO), "--version"], capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    banner = (p.stdout + p.stderr).strip()
    return banner.split()[-1] if banner else MAXCSO_VERSION  # "maxcso v1.13.0" -> "v1.13.0"


def main() -> None:
    if not MAXCSO.exists():
        raise SystemExit(f"maxcso not vendored at {MAXCSO}; run seedtools/vendor_tools.py maxcso")
    if not ISO.exists():
        raise SystemExit(f"source ISO missing at {ISO}; run seedtools/make_iso_fixture.py")

    out = ROOT / "fixtures" / "cso" / "synthetic"
    out.mkdir(parents=True, exist_ok=True)
    cso_path = out / "game.cso"

    # 1. compress the inner ISO to a CISO with the third-party author
    subprocess.run([str(MAXCSO), str(ISO), "-o", str(cso_path)], capture_output=True, check=True)

    # 2. structural anchor — maxcso round-trips the .cso back to the exact ISO
    rt = out / "_roundtrip.iso"
    try:
        subprocess.run(
            [str(MAXCSO), "--decompress", str(cso_path), "-o", str(rt)],
            capture_output=True, check=True,
        )
        if sha256_of(rt) != sha256_of(ISO):
            raise SystemExit("maxcso --decompress does not reproduce the source ISO byte-exact")
    finally:
        rt.unlink(missing_ok=True)

    # 3. expected manifest — entries from pycdlib (second reader), format="cso",
    #    source fields describe the decompressed inner ISO (the truth).
    entries = entries_from_pycdlib(ISO)
    tools = {
        "maxcso": maxcso_version(),
        "pycdlib": dist_version("pycdlib"),
        "generator": GENERATOR,
    }
    tree = FileTree(source=FileSource(ISO), format="cso", entries=tuple(entries))
    manifest = canonical_manifest(tree, "game.cso", sha256_of(ISO), tools)
    (out / "expected.manifest.json").write_bytes(manifest)

    print(
        f"wrote {cso_path} ({cso_path.stat().st_size} bytes) from {ISO.name} "
        f"({ISO.stat().st_size} bytes); "
        f"{sum(1 for e in entries if e.kind == 'file')} files / "
        f"{sum(1 for e in entries if e.kind == 'dir')} dirs; tools={tools}"
    )


if __name__ == "__main__":
    main()
