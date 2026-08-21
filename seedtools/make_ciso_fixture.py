#!/usr/bin/env python3
"""Author the synthetic CISO fixture (NORMALIZERS.md row `ciso`).

Hand-packs wit's compact-ISO container — the layout characterized in
substratum/formats/ciso.py — around the committed iso9660 synthetic disc
(the same inner-truth reuse the cso unit built on):

  block 0  present: the full synthetic.iso (169,984 bytes) padded to one
           2 MiB slot with a documented sha256-chain pattern;
  block 1  absent  : zero-filled on decode;
  block 2  present: a second sha256-chain slot, deliberately NOT at slot
           index == block index (it is slot 1), so a parser that maps
           blocks to slots by index instead of present-rank serves wrong
           bytes and dies in the tests;
  block 3+ absent.

The expected manifest's entries are authored from pycdlib's OWN records
(entries_from_pycdlib — the second reader, never substratum's parser).
source.sha256/size describe the DECODED VIEW (payload slots zero-padded
out to the fixed 4,699,979,776-byte address space), per the
spooled-container convention. Only game.ciso and expected.manifest.json
are written under fixtures/ciso/synthetic/.
"""

import hashlib
import struct
import sys
from importlib.metadata import version as dist_version
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from make_iso_fixture import entries_from_pycdlib

from substratum.contract import FileTree, canonical_manifest

GENERATOR = "make_ciso_fixture v1"
ROOT = Path(__file__).resolve().parent.parent
ISO = ROOT / "fixtures" / "iso9660" / "synthetic" / "synthetic.iso"
BLOCK = 0x200000
TOTAL = 4_699_979_776
NBLOCKS = (TOTAL + BLOCK - 1) // BLOCK  # 2242
HEADER_AREA = 0x8000
CHUNK = 1 << 20


class _DecodedView:
    """Size-only stand-in for the decoded view (the manifest's source
    identity is the view, not the container file)."""

    def size(self) -> int:
        return TOTAL


def chain_block(seed: bytes, size: int) -> bytes:
    out = bytearray()
    digest = hashlib.sha256(seed).digest()
    while len(out) < size:
        out += digest
        digest = hashlib.sha256(digest).digest()
    return bytes(out[:size])


def view_sha256(slot_for_block: dict[int, bytes]) -> str:
    """Hash the decoded view: each present block's payload, zeros for
    absent blocks, out to the fixed total (streamed, never materialized)."""
    h = hashlib.sha256()
    for block in range(NBLOCKS):
        payload = slot_for_block.get(block)
        want = min(BLOCK, TOTAL - block * BLOCK)
        if payload is not None:
            h.update(payload)
        else:
            pos = 0
            while pos < want:
                h.update(bytes(min(CHUNK, want - pos)))
                pos += CHUNK
    return h.hexdigest()


def main() -> None:
    if not ISO.exists():
        raise SystemExit(f"source ISO missing at {ISO}; run seedtools/make_iso_fixture.py")

    block0 = ISO.read_bytes() + chain_block(b"ciso-synthetic-block0-tail", BLOCK - ISO.stat().st_size)
    block2 = chain_block(b"ciso-synthetic-block2", BLOCK)

    present = {0: block0, 2: block2}
    header = bytearray(HEADER_AREA)
    header[0:4] = b"CISO"
    struct.pack_into("<I", header, 4, BLOCK)
    for block in present:
        header[8 + block] = 1

    out = ROOT / "fixtures" / "ciso" / "synthetic"
    out.mkdir(parents=True, exist_ok=True)
    ciso_path = out / "game.ciso"
    ciso_path.write_bytes(bytes(header) + block0 + block2)

    vsha = view_sha256(present)
    entries = entries_from_pycdlib(ISO)
    tools = {"generator": GENERATOR, "pycdlib": dist_version("pycdlib")}
    tree = FileTree(source=_DecodedView(), format="ciso", entries=tuple(entries))
    manifest = canonical_manifest(tree, ciso_path.name, vsha, tools)
    (out / "expected.manifest.json").write_bytes(manifest)

    print(
        f"wrote {ciso_path} ({ciso_path.stat().st_size} bytes): blocks 0,2 present "
        f"of {NBLOCKS}; payload = {ISO.name} padded to one slot + one chain slot\n"
        f"decoded view sha256 = {vsha}\n"
        f"{sum(1 for e in entries if e.kind == 'file')} files / "
        f"{sum(1 for e in entries if e.kind == 'dir')} dirs; tools={tools}"
    )


if __name__ == "__main__":
    main()
