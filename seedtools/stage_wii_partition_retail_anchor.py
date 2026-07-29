#!/usr/bin/env python3
"""Stage The Munchables DATA partition as metadata-only keyed-Wii proof.

The ``wii-partition`` normalizer decrypts a Wii partition into a lazy
``ByteView`` of 0x7C00-byte cluster payloads. Proving it on retail bytes
requires the operator-supplied standard Wii common key
(``fixtures/_local/wii-common-key.bin``) AND an independent oracle for the
decrypted output. This seedtool uses pinned ``wit`` as that oracle.

Independence contract (AGENTS.md §3): reference bytes come from wit's
extraction, never from the normalizer under test. wit fully decrypts and
extracts the partition to a temp dir; this tool copies a bounded sample of
the extracted files (those at known, fixed decrypted-partition offsets per
the GC/Wii disc layout — yagcd) into the gitignored ``reference/`` area and
publishes only a manifest of their decrypted offsets, sizes, and SHA-256
hashes. No key bytes and no decrypted retail payloads are committed; only
provenance + the manifest commit.

The runtime normalizer is not imported. Truth is wit's extraction + the
public disc layout, both independent of the parser under test.

Usage:
    uv run python seedtools/stage_wii_partition_retail_anchor.py [<wii-iso>]

Requires:
    - fixtures/_local/The Munchables (USA).iso
    - fixtures/_local/wii-common-key.bin  (16 raw bytes; standard Wii key)
    - tools/wit/wit.exe  (vendored via seedtools/vendor_tools.py wit)
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from seedtools import vendor_tools  # noqa: E402
from substratum.contract import FileSource  # noqa: E402
from substratum.formats.wii_disc import normalize_wii_disc  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ISO = ROOT / "fixtures" / "_local" / "The Munchables (USA).iso"
KEY_FILE = ROOT / "fixtures" / "_local" / "wii-common-key.bin"
OUTPUT = ROOT / "fixtures" / "wii_partition" / "munchables"

GENERATOR = "stage_wii_partition_retail_anchor v1"
TOOL_TIMEOUT_SECONDS = 600

# Sample of decrypted DATA-partition regions at known FIXED offsets (yagcd /
# wiibrew GC disc layout). These three sit at positions that are fixed by the
# disc spec, independent of per-title apploader/dol sizes, so their raw
# decrypted-stream offsets are independently known. (fst.bin and main.dol are
# variable-position — their offsets require FST parsing, which is wii-fst's
# layer — so they are intentionally excluded from this partition-level proof.)
SAMPLE = [
    # (extracted rel path, decrypted offset, description)
    ("sys/boot.bin", 0x0000, "disc header (0x440)"),
    ("sys/bi2.bin", 0x0440, "region settings (0x2000)"),
    ("sys/apploader.img", 0x2440, "apploader"),
]

EXPECTED_ISO_SHA256 = (
    "64c012f35d0c8b97e34c13e47060550b36d89fc36bed2691661cfdf108671cbb"
)


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


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _extract_with_wit(wit_version: str, iso: Path) -> Path:
    """Extract the decrypted partition with wit into a temp dir; return it."""
    wit_exe = ROOT / "tools" / "wit" / "wit.exe"
    tmp = Path(tempfile.mkdtemp(prefix="wii-partition-wit-"))
    # wit refuses a non-empty destination and wants a clean target subdir.
    dest = tmp / "extracted"
    _run_text([str(wit_exe), "extract", str(iso), "-d", str(dest)])
    data_dir = dest / "DATA"
    if not data_dir.is_dir():
        shutil.rmtree(tmp, ignore_errors=True)
        raise SystemExit("wit extraction produced no DATA/ directory")
    return dest


def _stage_references(extracted: Path) -> tuple[Path, list[dict]]:
    """Copy the sampled wit-extracted files into the gitignored reference dir.

    Returns ``(reference_dir, manifest_entries)`` where each entry records the
    decrypted offset, size, and SHA-256 of wit's independent extraction."""
    reference = OUTPUT / "reference"
    if reference.exists():
        shutil.rmtree(reference)
    reference.mkdir(parents=True)
    entries: list[dict] = []
    for rel, offset, desc in SAMPLE:
        src = extracted / "DATA" / rel
        if not src.is_file():
            raise SystemExit(f"wit did not extract {rel}")
        size = src.stat().st_size
        digest = _sha256(src)
        # Flatten into reference/<basename> to keep the gate's path scheme simple.
        dst = reference / Path(rel).name
        shutil.copy2(src, dst)
        entries.append(
            {
                "path": Path(rel).name,
                "decrypted_offset": offset,
                "size": size,
                "sha256": digest,
                "source": rel,
                "description": desc,
            }
        )
    return reference, entries


def main() -> None:
    if len(sys.argv) > 2:
        raise SystemExit(__doc__)
    iso = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else DEFAULT_ISO
    if not iso.is_file():
        raise SystemExit(f"Wii ISO not found: {iso}")
    if not KEY_FILE.is_file():
        raise SystemExit(
            f"common key not found: {KEY_FILE} (see docs/WII-KEYED-WORK.md)"
        )
    if KEY_FILE.stat().st_size != 16:
        raise SystemExit(
            f"common key must be exactly 16 bytes (got {KEY_FILE.stat().st_size})"
        )
    from substratum.contract import sha256_of  # noqa: E402

    iso_hash = sha256_of(iso)
    if iso_hash != EXPECTED_ISO_SHA256:
        raise SystemExit(
            f"ISO sha256 drift: {iso_hash} != validated anchor"
        )

    # Confirm the wii-disc layer still resolves the DATA partition consistently.
    tree = normalize_wii_disc(FileSource(iso))
    data_entry = next(
        e for e in tree.entries if e.path == "partition-data.bin"
    )

    wit_version = _check_wit()
    extracted = _extract_with_wit(wit_version, iso)
    try:
        reference, entries = _stage_references(extracted)
    finally:
        shutil.rmtree(extracted, ignore_errors=True)

    OUTPUT.mkdir(parents=True, exist_ok=True)
    doc = {
        "generator": GENERATOR,
        "source_iso": {
            "name": iso.name,
            "sha256": iso_hash,
            "data_partition": {
                "offset": data_entry.offset,
                "size": data_entry.size,
            },
        },
        "oracle": {
            "wit": wit_version,
            "method": "wit extract — full independent decrypt + FST extract",
        },
        "layout": "GC/Wii decrypted DATA partition (yagcd/wiibrew)",
        "samples": sorted(entries, key=lambda e: e["decrypted_offset"]),
    }
    (OUTPUT / "expected.manifest.json").write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    sample_bytes = sum(e["size"] for e in entries)
    print(
        f"staged Munchables DATA partition proof:\n"
        f"  {len(entries)} sampled regions, {sample_bytes} reference bytes\n"
        f"  manifest -> {OUTPUT / 'expected.manifest.json'}\n"
        f"  reference bytes (gitignored) -> {reference}"
    )


if __name__ == "__main__":
    main()
