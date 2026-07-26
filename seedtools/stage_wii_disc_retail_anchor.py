#!/usr/bin/env python3
"""Stage The Munchables as metadata-only unkeyed Wii disc proof.

Usage:
    uv run python seedtools/stage_wii_disc_retail_anchor.py [<wii-iso>]

The runtime normalizer is not imported. Fixture truth comes independently
from pinned wit's partition report and verification result. The retail disc
and opaque partition references stay gitignored; only the canonical manifest
and provenance commit.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from seedtools import vendor_tools  # noqa: E402
from substratum.contract import (  # noqa: E402
    FileEntry,
    FileSource,
    FileTree,
    canonical_manifest,
)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ISO = ROOT / "fixtures" / "_local" / "The Munchables (USA).iso"
OUTPUT = ROOT / "fixtures" / "wii_disc" / "munchables"

GENERATOR = "stage_wii_disc_retail_anchor v1"
EXPECTED_SIZE = 4_699_979_776
EXPECTED_HASHES = {
    "crc32": "ab7f4478",
    "md5": "2e2592f013d1d7cad7a9e54ab1521495",
    "sha1": "2b7706b9f3cd251922c72fddfdcf35231b77012c",
    "sha256": "64c012f35d0c8b97e34c13e47060550b36d89fc36bed2691661cfdf108671cbb",
}
EXPECTED_ID = "RQCEAF"
EXPECTED_PARTITIONS = {
    0: {
        "label": "UPDATE",
        "type": 1,
        "offset": 0x50000,
        "size": 0xB2A8000,
        "path": "partition-update.bin",
        "status": "enc,signed",
        "sha256": (
            "61338bbb4ea345521b103c04908101ef78fb03159d7f24026c701a7b66b7fdec"
        ),
    },
    1: {
        "label": "DATA",
        "type": 0,
        "offset": 0xF800000,
        "size": 0x107BC0000,
        "path": "partition-data.bin",
        "status": "enc,signed,scrub",
        "sha256": (
            "0c1af607b6c22d41eaa661fbb3ffd18bf9bf95acf473769fc43712d032d1a3e0"
        ),
    },
}
TOOL_TIMEOUT_SECONDS = 600


def _hashes(path: Path) -> dict[str, str]:
    crc = 0
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            crc = zlib.crc32(chunk, crc)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "crc32": f"{crc & 0xffffffff:08x}",
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


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
            f"tool failed with exit {process.returncode}: {command[0]}"
        )
    return process.stdout + process.stderr


def _check_wit() -> tuple[Path, str]:
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
    return wit, first.split(":", 1)[1].strip()


def _partitions_from_wit(
    wit: Path, iso: Path
) -> dict[int, dict[str, int | str]]:
    output = _run_text([str(wit), "dump", "--long", "--long", str(iso)])
    required = {
        "disc identity": rf"Disc & part IDs:\s+disc={EXPECTED_ID},",
        "disc kind": r"File & disc type:\s+ISO/WII\s+&\s+Wii",
        "partition count": r"Partitions:\s+2\s+\[encrypted, scrubbed, well signed\]",
        "partition table count": r"1 partition table with 2 partitions:",
    }
    for description, pattern in required.items():
        if re.search(pattern, output) is None:
            raise SystemExit(f"wit {description} check failed")

    pattern = re.compile(
        r"^\s+0\.(?P<index>[01])\s+"
        r"(?P<label>UPDATE|DATA)\s+"
        r"(?P<type>[01])\s+"
        r"(?P<offset>[0-9A-Fa-f]+)\s+\.\.\s+"
        r"(?P<end>[0-9A-Fa-f]+)\s+"
        r"(?P<size_hex>[0-9A-Fa-f]+)\s+=\s+"
        r"(?P<size_dec>\d+)\s+=\s+\d+\s+"
        r"(?P<status>enc,signed(?:,scrub)?)\s*$",
        re.MULTILINE,
    )
    found: dict[int, dict[str, int | str]] = {}
    for match in pattern.finditer(output):
        index = int(match.group("index"))
        offset = int(match.group("offset"), 16)
        end = int(match.group("end"), 16)
        size_hex = int(match.group("size_hex"), 16)
        size_dec = int(match.group("size_dec"))
        if end - offset != size_hex or size_hex != size_dec:
            raise SystemExit(f"wit partition {index} size representations differ")
        found[index] = {
            "label": match.group("label"),
            "type": int(match.group("type")),
            "offset": offset,
            "size": size_dec,
            "status": match.group("status"),
        }

    expected = {
        index: {
            "label": values["label"],
            "type": values["type"],
            "offset": values["offset"],
            "size": values["size"],
            "status": values["status"],
        }
        for index, values in EXPECTED_PARTITIONS.items()
    }
    if found != expected:
        raise SystemExit(f"wit partition table drift: {found}")
    return found


def _verify_partitions(wit: Path, iso: Path) -> None:
    output = _run_text([str(wit), "verify", "--long", str(iso)])
    successes = re.findall(
        rf"^\+OK\s+\.([01])\s+(UPDATE|DATA)\s+{EXPECTED_ID}\s+",
        output,
        re.MULTILINE,
    )
    if successes != [("0", "UPDATE"), ("1", "DATA")]:
        raise SystemExit(f"wit partition verification drift: {successes}")


def _copy_range(
    source: Path, destination: Path, offset: int, size: int
) -> str:
    digest = hashlib.sha256()
    remaining = size
    with source.open("rb") as src, destination.open("wb") as dst:
        src.seek(offset)
        while remaining:
            chunk = src.read(min(1 << 20, remaining))
            if not chunk:
                raise SystemExit("short read while staging a Wii partition")
            dst.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def _stage_references(iso: Path) -> Path:
    reference = OUTPUT / "reference"
    with tempfile.TemporaryDirectory(
        prefix="wii-disc-reference-", dir=OUTPUT
    ) as temp:
        temporary = Path(temp)
        for values in EXPECTED_PARTITIONS.values():
            path = temporary / str(values["path"])
            digest = _copy_range(
                iso,
                path,
                int(values["offset"]),
                int(values["size"]),
            )
            if digest != values["sha256"]:
                raise SystemExit(
                    f"partition hash mismatch for {values['path']}"
                )
        if reference.exists():
            shutil.rmtree(reference)
        temporary.replace(reference)
    return reference


def main() -> None:
    if len(sys.argv) > 2:
        raise SystemExit(__doc__)
    iso = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else DEFAULT_ISO
    if not iso.is_file():
        raise SystemExit(f"Wii ISO not found: {iso}")
    if iso.stat().st_size != EXPECTED_SIZE:
        raise SystemExit(
            f"ISO size {iso.stat().st_size} != validated size {EXPECTED_SIZE}"
        )
    hashes = _hashes(iso)
    if hashes != EXPECTED_HASHES:
        raise SystemExit(f"ISO hashes do not match the validated anchor: {hashes}")

    wit, wit_version = _check_wit()
    partitions = _partitions_from_wit(wit, iso)
    _verify_partitions(wit, iso)

    OUTPUT.mkdir(parents=True, exist_ok=True)
    reference = _stage_references(iso)
    entries = tuple(
        FileEntry(
            path=str(EXPECTED_PARTITIONS[index]["path"]),
            kind="file",
            offset=int(values["offset"]),
            size=int(values["size"]),
        )
        for index, values in sorted(partitions.items())
    )
    tools = {"generator": GENERATOR, "wit": wit_version}
    tree = FileTree(FileSource(iso), "wii-disc", entries)
    manifest = canonical_manifest(
        tree, iso.name, hashes["sha256"], tools
    )
    manifest_path = OUTPUT / "expected.manifest.json"
    manifest_path.write_bytes(manifest)
    print(
        f"validated {iso.name}: {EXPECTED_SIZE} bytes, "
        f"{len(entries)} encrypted partitions\n"
        f"manifest -> {manifest_path}\n"
        f"reference bytes (gitignored) -> {reference}"
    )


if __name__ == "__main__":
    main()
