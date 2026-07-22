#!/usr/bin/env python3
"""Build a nested-directory GameCube FST fixture (S2 proof-strengthening).

This is the "recipe" for fixtures/gc_fst/nested/ per the design spec
(docs/superpowers/specs/2026-07-22-gc-fst-nested-fixture-design.md). It
materializes a complete GC disc image with a hand-authored *nested* FST,
then derives the expected manifest from wit's independent decode of that
FST (never from substratum's own parser — AGENTS.md § 3 independence).

Why a hand-authored image rather than `wit COPY --source <dir>`: wit cannot
*compose* a GameCube ISO from an extracted directory (it always emits Wii —
wiimms-iso-tools issue #24, unresolved on v3.05a r8638). But wit CAN *read*
a complete hand-authored GC disc, and independently decodes the nested FST
— so it serves as a genuine two-party differential on nested bytes.

The committed fixture carries only the metadata manifest. The ~1.4 GiB disc
image (padded to GC disc size) and the wit-extracted reference bytes are
gitignored, materialized by this seedtool on demand. The image borrows the
retail Hulk's `sys/` region (boot/bi2/apploader/main.dol) so wit validates
the disc structure; it is built from the gitignored retail ISO in
fixtures/_local/game.iso and never enters git.

Usage: python seedtools/make_gc_fst_nested_fixture.py
"""

from __future__ import annotations

import hashlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from substratum.contract import FileEntry, FileSource, FileTree, canonical_manifest, sha256_of

_WIT_REL = Path("tools") / "wit" / "wit.exe"
STAGER = "make_gc_fst_nested_fixture v1"

# --- GC disc constants (mirror gc_fst.py; duplicated to keep the seedtool
#     independent of the module under test) --------------------------------
_GC_MAGIC = 0xC2339F3D
_MAGIC_OFF = 0x01C
_FST_OFF = 0x424
_FST_SIZE = 0x428
_DOL_OFF = 0x420
_NODE_SIZE = 0x0C
# Full GC disc size — wit requires the image padded out to this.
_GC_DISC_SIZE = 1_459_978_240

# Synthetic disc id ("TESTN01" = nested test). 6 chars + version byte.
_DISC_ID = b"TESTN01\x00"

# Standard GC disc layout offsets (the real Hulk uses these; borrowing them
# keeps the apploader's size fields valid so wit accepts the disc).
_HEADER_LEN = 0x440
_BI2_OFF = 0x440
_APPLOADER_OFF = 0x2440


# --- The nested FST recipe (design spec §5.1/§5.2) -----------------------
# files/
#   top.txt
#   data/
#     mid.txt
#     nested/
#       deep.txt
#     after.txt      <- sibling AFTER nested/ closes (the resume edge case)
#
# Node table:
#   0: root    dir  name=""       parent=0 next=7
#   1: top.txt      file
#   2: data    dir  name="data"   parent=0 next=7   (children: 3,4,6)
#   3: mid.txt      file
#   4: nested  dir  name="nested" parent=2 next=6   (child: 5)
#   5: deep.txt     file
#   6: after.txt    file                            (data's last child)
_FILES = ["top.txt", "data/mid.txt", "data/nested/deep.txt", "data/after.txt"]
_DIRS = ["data", "data/nested"]


def _wit_exe() -> Path:
    root = Path(__file__).resolve().parent.parent
    exe = root / _WIT_REL
    if not exe.exists():
        raise SystemExit(f"wit not found at {exe}; re-vendor via seedtools/vendor_tools.py")
    return exe


def wit_version(exe: Path) -> str:
    out = subprocess.run([str(exe), "version"], capture_output=True, text=True, check=True)
    first = out.stdout.strip().splitlines()[0]
    return first.split(":", 1)[1].strip() if first.lower().startswith("wit:") else first


def _payload(path: str) -> bytes:
    """Deterministic file bytes keyed on path (same path -> same bytes).

    A path-derived 64-byte block repeated to a path-derived length, so check 4
    has real non-trivial content and the manifest is stable across regenerations.
    """
    h = hashlib.sha256(path.encode("ascii")).digest()  # 32 bytes
    block = (h + h)[:64]  # 64-byte block
    # length: 40..200, derived from the path so each file differs in size
    length = 40 + (sum(path.encode("ascii")) % 161)
    return (block * (length // 64 + 1))[:length]


def _build_fst(file_offsets: dict[str, tuple[int, int]]) -> bytes:
    """Encode the 7-node nested FST + string table.

    `file_offsets` maps each file path to (offset, size) in the disc image.
    """
    # String table: offset 0 = root's empty name, then names in node order.
    strings = bytearray(b"\x00")  # node 0 (root) -> ""

    def add_name(name: str) -> int:
        off = len(strings)
        strings.extend(name.encode("ascii"))
        strings.append(0)
        return off

    n_top = add_name("top.txt")
    n_data = add_name("data")
    n_mid = add_name("mid.txt")
    n_nested = add_name("nested")
    n_deep = add_name("deep.txt")
    n_after = add_name("after.txt")

    off_top, size_top = file_offsets["top.txt"]
    off_mid, size_mid = file_offsets["data/mid.txt"]
    off_deep, size_deep = file_offsets["data/nested/deep.txt"]
    off_after, size_after = file_offsets["data/after.txt"]

    def node(type_: int, name_off: int, f1: int, f2: int) -> bytes:
        return bytes([type_]) + name_off.to_bytes(3, "big") + struct.pack(">II", f1, f2)

    nodes = b"".join([
        node(1, 0, 0, 7),                              # 0: root dir, next=7
        node(0, n_top, off_top, size_top),             # 1: top.txt
        node(1, n_data, 0, 7),                         # 2: data dir, parent=0 next=7
        node(0, n_mid, off_mid, size_mid),             # 3: mid.txt
        node(1, n_nested, 2, 6),                       # 4: nested dir, parent=2 next=6
        node(0, n_deep, off_deep, size_deep),          # 5: deep.txt
        node(0, n_after, off_after, size_after),       # 6: after.txt
    ])
    return nodes + bytes(strings)


def build_image(retail_iso: Path, dest: Path) -> Path:
    """Materialize the nested GC disc image at `dest`.

    Grafts the retail disc's sys/ region (boot header, bi2, apploader, dol)
    and appends the hand-authored nested FST + payloads, padded to GC size.
    """
    exe = _wit_exe()
    with tempfile.TemporaryDirectory(prefix="gc_nested_") as td:
        tdp = Path(td)
        # wit extract refuses existing dirs; point it at a fresh subdir.
        extract_target = tdp / "extract"
        subprocess.run(
            [str(exe), "extract", str(retail_iso), str(extract_target)],
            capture_output=True, check=True,
        )
        pdir = next(extract_target.glob("P-*/"), None)
        if pdir is None or not (pdir / "sys").is_dir():
            raise SystemExit(f"wit extract produced no P-*/sys/ under {extract_target}")
        sys_dir = pdir / "sys"

        boot = (sys_dir / "boot.bin").read_bytes()
        bi2 = (sys_dir / "bi2.bin").read_bytes()
        apploader = (sys_dir / "apploader.img").read_bytes()
        dol = (sys_dir / "main.dol").read_bytes()
        if len(boot) < _HEADER_LEN:
            raise SystemExit(f"boot.bin too short: {len(boot)} bytes")

        # The real disc's dol offset (0x420) — reuse it so the apploader's
        # embedded size/address fields stay valid for wit.
        dol_off = struct.unpack(">I", boot[_DOL_OFF:_DOL_OFF + 4])[0]
        if dol_off == 0:
            dol_off = 0x1EC00  # standard fallback
        if dol_off + len(dol) > _GC_DISC_SIZE:
            raise SystemExit("dol placement overflows disc size")

        # File payloads go right after the dol, 4-byte aligned.
        cursor = (dol_off + len(dol) + 3) & ~3
        file_offsets: dict[str, tuple[int, int]] = {}
        for path in _FILES:
            data = _payload(path)
            file_offsets[path] = (cursor, len(data))
            cursor += len(data)
            cursor = (cursor + 3) & ~3

        # FST goes after the payloads, 4-byte aligned.
        fst_off = (cursor + 3) & ~3
        fst = _build_fst(file_offsets)
        fst_size = len(fst)
        content_end = fst_off + fst_size
        if content_end > _GC_DISC_SIZE:
            raise SystemExit("FST placement overflows disc size")

        # Assemble the image.
        img = bytearray(_GC_DISC_SIZE)
        # Header region (0..0x440) from boot.bin, then patch the fields we own.
        img[0:len(boot)] = boot
        img[0:len(_DISC_ID)] = _DISC_ID  # synthetic disc id
        struct.pack_into(">I", img, _MAGIC_OFF, _GC_MAGIC)  # GC magic
        struct.pack_into(">I", img, _FST_OFF, fst_off)
        struct.pack_into(">I", img, _FST_SIZE, fst_size)
        # bi2 + apploader + dol at their standard offsets.
        img[_BI2_OFF:_BI2_OFF + len(bi2)] = bi2
        img[_APPLOADER_OFF:_APPLOADER_OFF + len(apploader)] = apploader
        img[dol_off:dol_off + len(dol)] = dol
        # File payloads.
        for path in _FILES:
            off, size = file_offsets[path]
            img[off:off + size] = _payload(path)
        # FST.
        img[fst_off:fst_off + fst_size] = fst

        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("wb") as f:
            f.write(img)
    return dest


# wit files-ll row parsers (shared shape with stage_gc_fst.py).
_FILE_ROW = re.compile(r"^\s*([0-9a-fA-F]+)\+\s+([0-9a-fA-F]+)\s+(\d+)\s+(.+)$")
_DIR_ROW = re.compile(r"^\s*-\s+-\s+N=(\d+)\s+(.+)/\s*$")


def entries_from_wit_listing(exe: Path, iso: Path) -> list[FileEntry]:
    """Parse wit files-ll into FileEntries — the independent reader.

    Takes only real user-data entries under <PREFIX>/files/, normalizing to
    bare relative posix paths (nested paths survive intact). Virtual sys/
    entries and root scripts are excluded: they are not FST records.
    """
    out = subprocess.run(
        [str(exe), "files-ll", str(iso)], capture_output=True, text=True, check=True
    )
    entries: list[FileEntry] = []
    for line in out.stdout.splitlines():
        m = _FILE_ROW.match(line)
        if not m:
            # directory rows are captured separately for the manifest
            d = _DIR_ROW.match(line)
            if d:
                path = d.group(2).strip()
                # keep only real subdirs under files/ — skip the files/ root
                # dir row itself (it is not an FST entry, just wit's grouping).
                marker = "/files/"
                idx = path.find(marker)
                if idx >= 0:
                    name = path[idx + len(marker):].strip()
                    if name:  # non-empty => a real subdir like "data" or "data/nested"
                        entries.append(FileEntry(path=name.rstrip("/"), kind="dir", offset=0, size=0))
            continue
        off_hex, _size_hex, size_dec, path = m.group(1), m.group(2), m.group(3), m.group(4)
        path = path.strip()
        marker = "/files/"
        idx = path.find(marker)
        if idx < 0:
            continue
        name = path[idx + len(marker):]
        if not name:
            continue
        entries.append(
            FileEntry(path=name, kind="file", offset=int(off_hex, 16), size=int(size_dec))
        )
    entries.sort(key=lambda e: e.path)
    return entries


def extract_reference(exe: Path, iso: Path, dest: Path) -> Path:
    """Run `wit extract`, return the path to the extracted P-*/files dir."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / "extract"
    subprocess.run(
        [str(exe), "extract", str(iso), str(target)],
        capture_output=True, check=True,
    )
    pdir = next(target.glob("P-*/"), None)
    if pdir is None or not (pdir / "files").is_dir():
        raise SystemExit(f"wit extract produced no P-*/files/ under {target}")
    return pdir / "files"


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    retail_iso = root / "fixtures" / "_local" / "game.iso"
    if not retail_iso.exists():
        raise SystemExit(
            f"retail ISO not found: {retail_iso}\n"
            "(nested fixture borrows its sys/ region; drop a GC ISO per the FIXTURE REQUEST)"
        )
    out_dir = root / "fixtures" / "gc_fst" / "nested"
    out_dir.mkdir(parents=True, exist_ok=True)
    image = out_dir / "game.iso"

    exe = _wit_exe()
    print(f"building nested disc image (sys from {retail_iso.name})...")
    build_image(retail_iso, image)
    print(f"  -> {image} ({image.stat().st_size} bytes)")

    # Independent decode via wit — the manifest's source of truth.
    entries = entries_from_wit_listing(exe, image)
    if not entries:
        raise SystemExit("no file entries parsed from wit files-ll — aborting")
    nfiles = sum(1 for e in entries if e.kind == "file")
    ndirs = sum(1 for e in entries if e.kind == "dir")
    print(f"wit decoded {nfiles} files + {ndirs} dirs")

    files_src = extract_reference(exe, image, out_dir / "reference")
    ref_root = out_dir / "reference"
    for e in entries:
        if e.kind != "file":
            continue
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
    tree = FileTree(source=FileSource(image), format="gc-fst", entries=tuple(entries))
    manifest = canonical_manifest(tree, image.name, sha256_of(image), tools)
    (out_dir / "expected.manifest.json").write_bytes(manifest)

    print(f"manifest -> {out_dir / 'expected.manifest.json'}")
    print(f"reference bytes (NOT committed) -> {ref_root}")


if __name__ == "__main__":
    main()
