#!/usr/bin/env python3
"""Stage Cubic Ninja (Japan) as metadata-only 3DS CCI proof.

Usage:
    uv run python seedtools/stage_3ds_cci_retail_anchor.py [<cci-file>]

The runtime normalizer is not imported.  Fixture truth comes independently
from pinned ctrtool's partition table plus pinned 3dstool's extracted bytes.
The retail CCI and extracted partition payloads stay gitignored; only the
canonical manifest and provenance commit.
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
DEFAULT_CCI = ROOT / "fixtures" / "_local" / "Cubic Ninja (Japan).3ds"
OUTPUT = ROOT / "fixtures" / "3ds_cci" / "cubic-ninja"

GENERATOR = "stage_3ds_cci_retail_anchor v1"
EXPECTED_SIZE = 134_217_728
EXPECTED_HASHES = {
    "crc32": "240b07ee",
    "md5": "fc2ae27ca7848fed31c37d8e70700c2d",
    "sha1": "2ee5cacaeedcb413d48f8b1e3aa2e09d16051148",
    "sha256": "929a675e4dedd315fd6ef5565e6d97b3fd7cd281171c14f2fa0a5163b7096b42",
}
EXPECTED_TITLE_ID = "0004000000034300"
EXPECTED_PARTITIONS = {
    0: {
        "id": "0004000000034300",
        "offset": 16_384,
        "size": 86_430_720,
        "path": "partition0.cxi",
        "sha256": "b805cdfdf2965e8a6f90990982bf7386ba755811bea52c5d0902bbb799a6af80",
    },
    7: {
        "id": "80000000000b4300",
        "offset": 86_447_104,
        "size": 5_116_416,
        "path": "partition7.cfa",
        "sha256": "ee478b0313c1bdf4e3a5440b1bac69f5f859fad5671ca61b4d3b7f062c6b5fd2",
    },
}


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


def _sha256_range(path: Path, offset: int, size: int) -> str:
    digest = hashlib.sha256()
    remaining = size
    with path.open("rb") as fh:
        fh.seek(offset)
        while remaining:
            chunk = fh.read(min(1 << 20, remaining))
            if not chunk:
                raise SystemExit("short read while hashing a CCI partition range")
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def _run_text(command: list[str], *, require_success: bool = True) -> str:
    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=vendor_tools.TOOL_TIMEOUT_SECONDS,
    )
    output = process.stdout + process.stderr
    if require_success and process.returncode != 0:
        raise SystemExit(
            f"tool failed with exit {process.returncode}: {command[0]}\n{output}"
        )
    return output


def _check_tools() -> tuple[Path, Path]:
    ctrtool = ROOT / "tools" / "ctrtool" / "ctrtool.exe"
    three_ds_tool = ROOT / "tools" / "3dstool" / "3dstool.exe"
    if not ctrtool.is_file() or not three_ds_tool.is_file():
        raise SystemExit(
            "pinned 3DS tools are absent; run "
            "`uv run python seedtools/vendor_tools.py 3ds`"
        )
    vendor_tools.check_pin(
        ctrtool, vendor_tools.CTRTOOL_EXE_SHA256, "ctrtool exe"
    )
    vendor_tools.check_pin(
        three_ds_tool, vendor_tools.THREEDSTOOL_EXE_SHA256, "3dstool exe"
    )
    ctr_banner = _run_text(
        [str(ctrtool), "--help"], require_success=False
    )
    if vendor_tools.CTRTOOL_BANNER not in ctr_banner:
        raise SystemExit("ctrtool version banner drift")
    three_ds_banner = _run_text(
        [str(three_ds_tool), "--help"], require_success=False
    ).strip().splitlines()[0]
    if three_ds_banner != vendor_tools.THREEDSTOOL_BANNER:
        raise SystemExit("3dstool version banner drift")
    return ctrtool, three_ds_tool


def _ctrtool_partitions(ctrtool: Path, cci: Path) -> dict[int, dict[str, int | str]]:
    output = _run_text([str(ctrtool), "-v", str(cci)])
    if not re.search(r"Header:\s+NCSD", output):
        raise SystemExit("ctrtool did not identify an NCSD header")
    title = re.search(r"TitleId:\s+([0-9A-Fa-f]{16})", output)
    if title is None or title.group(1).lower() != EXPECTED_TITLE_ID:
        raise SystemExit("ctrtool CCI title ID mismatch")

    pattern = re.compile(
        r" Partition (?P<slot>[0-7])\s+"
        r"Id:\s+(?P<id>[0-9A-Fa-f]{16})\s+"
        r"Area:\s+0x(?P<start>[0-9A-Fa-f]+)-0x(?P<end>[0-9A-Fa-f]+)",
        re.MULTILINE,
    )
    found: dict[int, dict[str, int | str]] = {}
    for match in pattern.finditer(output):
        slot = int(match.group("slot"))
        start = int(match.group("start"), 16)
        end = int(match.group("end"), 16)
        if slot in found:
            raise SystemExit(f"ctrtool listed partition slot {slot} twice")
        found[slot] = {
            "id": match.group("id").lower(),
            "offset": start,
            "size": end - start,
        }
    expected_view = {
        slot: {
            "id": values["id"],
            "offset": values["offset"],
            "size": values["size"],
        }
        for slot, values in EXPECTED_PARTITIONS.items()
    }
    if found != expected_view:
        raise SystemExit(f"ctrtool partition table drift: {found}")

    for slot, values in found.items():
        selected = _run_text(
            [str(ctrtool), "-v", "-n", str(slot), str(cci)]
        )
        ncch = re.search(
            r"NCCH:\s+Header:\s+NCCH.*?"
            r"Content size:\s+0x([0-9A-Fa-f]+).*?"
            r"Title id:\s+([0-9A-Fa-f]{16})",
            selected,
            re.DOTALL,
        )
        if ncch is None:
            raise SystemExit(f"ctrtool did not parse partition {slot} as NCCH")
        if (
            int(ncch.group(1), 16) != values["size"]
            or ncch.group(2).lower() != values["id"]
        ):
            raise SystemExit(f"ctrtool NCCH identity mismatch for partition {slot}")
    return found


def _extract_partitions(three_ds_tool: Path, cci: Path, destination: Path) -> None:
    command = [
        str(three_ds_tool),
        "-x",
        "-t",
        "cci",
        "-f",
        str(cci),
    ]
    for slot, values in sorted(EXPECTED_PARTITIONS.items()):
        command.extend([f"--partition{slot}", str(destination / values["path"])])
    _run_text(command)

    for values in EXPECTED_PARTITIONS.values():
        extracted = destination / values["path"]
        if not extracted.is_file():
            raise SystemExit(f"3dstool did not extract {values['path']}")
        if extracted.stat().st_size != values["size"]:
            raise SystemExit(f"3dstool size mismatch for {values['path']}")
        extracted_sha = _hashes(extracted)["sha256"]
        if extracted_sha != values["sha256"]:
            raise SystemExit(f"3dstool hash mismatch for {values['path']}")
        direct_sha = _sha256_range(cci, values["offset"], values["size"])
        if direct_sha != extracted_sha:
            raise SystemExit(
                f"3dstool bytes differ from direct CCI range for {values['path']}"
            )


def main() -> None:
    if len(sys.argv) > 2:
        raise SystemExit(__doc__)
    cci = Path(sys.argv[1]).resolve() if len(sys.argv) == 2 else DEFAULT_CCI
    if not cci.is_file():
        raise SystemExit(f"retail CCI not found: {cci}")
    if cci.stat().st_size != EXPECTED_SIZE:
        raise SystemExit(
            f"CCI size {cci.stat().st_size} != validated size {EXPECTED_SIZE}"
        )
    hashes = _hashes(cci)
    if hashes != EXPECTED_HASHES:
        raise SystemExit(f"CCI hashes do not match the validated anchor: {hashes}")

    ctrtool, three_ds_tool = _check_tools()
    partitions = _ctrtool_partitions(ctrtool, cci)

    OUTPUT.mkdir(parents=True, exist_ok=True)
    reference = OUTPUT / "reference"
    with tempfile.TemporaryDirectory(prefix="substratum-3ds-cci-") as temp:
        extracted = Path(temp)
        _extract_partitions(three_ds_tool, cci, extracted)
        if reference.exists():
            shutil.rmtree(reference)
        reference.mkdir()
        for values in EXPECTED_PARTITIONS.values():
            shutil.copy2(extracted / values["path"], reference / values["path"])

    entries = tuple(
        FileEntry(
            path=EXPECTED_PARTITIONS[slot]["path"],
            kind="file",
            offset=values["offset"],
            size=values["size"],
        )
        for slot, values in sorted(partitions.items())
    )
    tools = {
        "3dstool": vendor_tools.THREEDSTOOL_BANNER,
        "ctrtool": vendor_tools.CTRTOOL_BANNER,
        "generator": GENERATOR,
    }
    tree = FileTree(FileSource(cci), "3ds-cci", entries)
    manifest = canonical_manifest(tree, cci.name, hashes["sha256"], tools)
    manifest_path = OUTPUT / "expected.manifest.json"
    manifest_path.write_bytes(manifest)
    print(
        f"validated {cci.name}: {EXPECTED_SIZE} bytes, "
        f"{len(entries)} NCCH partitions\n"
        f"manifest -> {manifest_path}\n"
        f"reference bytes (gitignored) -> {reference}"
    )


if __name__ == "__main__":
    main()
