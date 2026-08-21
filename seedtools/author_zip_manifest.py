#!/usr/bin/env python3
"""Author the expected manifest for the synthetic ZIP fixture from 7-Zip's
independent listing (NORMALIZERS.md row `zip`; DESIGN §3 two-party rule).

Entry paths, kinds, and sizes come from `7z l -slt` — never from the
normalizer under test. Offsets follow the documented spool layout of
`substratum/formats/zip.py`: file payloads are spooled in ascending
path order (the same ordering `canonical_manifest` uses), back to back;
directory entries contribute nothing (offset 0, size 0).

Per the house convention for decode-spooled containers (see the `chd`
row), `source.name` identifies the input archive while `source.size`
and `source.sha256` describe the tree's underlying source — the spool.
Both are derived here from 7-Zip's own extraction (pulled to a temp dir
and concatenated in spool order), never from the normalizer.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from substratum.contract import canonical_manifest

SEVEN_ZIP_TIMEOUT_SECONDS = 120
SEVEN_ZIP = "7z"
DIFFERENTIAL = "7-Zip 26.02 (x64) 2026-06-25"
GENERATOR = "make_zip_fixture v1"

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "fixtures" / "zip" / "synthetic"


def _listing(archive: Path) -> list[dict[str, str]]:
    proc = subprocess.run(
        [SEVEN_ZIP, "l", "-slt", str(archive)],
        capture_output=True,
        text=True,
        check=True,
        timeout=SEVEN_ZIP_TIMEOUT_SECONDS,
    )
    entries: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        if not line.strip():
            if current:
                entries.append(current)
                current = {}
            continue
        match = re.match(r"^([A-Za-z ]+?) = (.*)$", line)
        if match:
            current[match.group(1)] = match.group(2)
    if current:
        entries.append(current)
    return [e for e in entries if "Path" in e and e["Path"] != str(archive)]


def main() -> None:
    archive = OUT / "game.zip"
    members = _listing(archive)

    files: list[tuple[str, int]] = []
    rows: list[tuple[str, str, int]] = []  # path, kind, size
    for member in members:
        path = member["Path"].replace("\\", "/")
        is_dir = member.get("Folder") == "+"
        size = int(member.get("Size") or 0)
        if is_dir:
            if size != 0:
                raise SystemExit(f"7-Zip lists directory {path!r} with size {size}")
            rows.append((path, "dir", 0))
        else:
            files.append((path, size))
            rows.append((path, "file", size))

    # Documented spool layout: file payloads in ascending path order.
    offsets: dict[str, int] = {}
    cursor = 0
    for path, size in sorted(files):
        offsets[path] = cursor
        cursor += size

    # Spool identity (size + sha256) from 7-Zip's own extraction,
    # concatenated in spool order — the chd convention for decoded output.
    with tempfile.TemporaryDirectory(prefix="substratum-zip-author-") as tmp:
        extract_dir = Path(tmp) / "x"
        subprocess.run(
            [SEVEN_ZIP, "x", str(archive), f"-o{extract_dir}", "-y"],
            capture_output=True,
            check=True,
            timeout=SEVEN_ZIP_TIMEOUT_SECONDS,
        )
        spool_hash = hashlib.sha256()
        for path, size in sorted(files):
            extracted = extract_dir / Path(*path.split("/"))
            if extracted.stat().st_size != size:
                raise SystemExit(
                    f"7-Zip extraction of {path!r} is {extracted.stat().st_size} "
                    f"bytes, listing said {size}"
                )
            with extracted.open("rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    spool_hash.update(chunk)

    entries = [
        {"path": path, "kind": kind, "offset": offsets.get(path, 0), "size": size}
        for path, kind, size in sorted(rows)
    ]

    class _Source:  # minimal duck-type for canonical_manifest
        def __init__(self, total: int) -> None:
            self._total = total

        def size(self) -> int:
            return self._total

    class _Tree:
        format = "zip"

        def __init__(self, total: int) -> None:
            self.source = _Source(total)

    class _Entry:
        def __init__(self, row: dict[str, object]) -> None:
            self.path = row["path"]
            self.kind = row["kind"]
            self.offset = row["offset"]
            self.size = row["size"]

    tree = _Tree(cursor)
    tree.entries = tuple(_Entry(e) for e in entries)
    tools = {
        "differential": DIFFERENTIAL,
        "generator": GENERATOR,
        "self-consistency": "structural-proof",
    }
    manifest = canonical_manifest(tree, archive.name, spool_hash.hexdigest(), tools)
    (OUT / "expected.manifest.json").write_bytes(manifest)
    print(f"authored expected.manifest.json from the 7-Zip listing "
          f"({len(entries)} entries, spool total {cursor} bytes)")


if __name__ == "__main__":
    main()
