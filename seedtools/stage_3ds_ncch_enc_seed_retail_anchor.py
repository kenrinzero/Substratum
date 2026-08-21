#!/usr/bin/env python3
"""Stage a 7.x-seed encrypted CIA as a metadata-only retail anchor.

Usage:
    uv run python seedtools/stage_3ds_ncch_enc_seed_retail_anchor.py \
        [<cia-file>] [<slug>]

The runtime normalizer is not imported. Fixture truth comes from pinned
ctrtool v1.3.0 (7.x keyslot `0x25` compiled in) + the operator-supplied
seeddb: ctrtool decrypts the whole CIA, verifies the NCCH protected hashes
(`-y`, all GOOD), and the decrypted regions are staged as gitignored
references. Only the canonical manifest and provenance commit.

3dstool cannot serve as a second-party decryptor here: it neither handles the
CIA container nor decrypts a raw 7.x-seed NCCH slice (both fail on the
encrypted header). The correctness anchor is therefore the NCCH-declared
protected SHA-256 hashes — cryptographic proof the decryption is byte-correct,
validated independently by ctrtool's `-y` verify pass AND by the runtime
normalizer composing the result through three_ds_ncch.
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

ROOT = Path(__file__).resolve().parent.parent
SEEDDB = ROOT / "fixtures" / "_local" / "seeddb.bin"

GENERATOR = "stage_3ds_ncch_enc_seed_retail_anchor v1"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
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


def _check_ctrtool() -> Path:
    ctrtool = ROOT / "tools" / "ctrtool" / "ctrtool.exe"
    if not ctrtool.is_file():
        raise SystemExit(
            "pinned ctrtool is absent; run "
            "`uv run python seedtools/vendor_tools.py 3ds`"
        )
    vendor_tools.check_pin(ctrtool, vendor_tools.CTRTOOL_EXE_SHA256, "ctrtool exe")
    if vendor_tools.CTRTOOL_BANNER not in _run_text(
        [str(ctrtool), "--help"], require_success=False
    ):
        raise SystemExit("ctrtool version banner drift")
    return ctrtool


def _field(report: str, label: str) -> str:
    m = re.search(rf"(?:^|\s){re.escape(label)}:\s*(.+)$", report, re.M)
    if m is None:
        raise SystemExit(f"ctrtool report omitted {label!r}")
    return m.group(1).strip()


def _hex(report: str, label: str) -> int:
    return int(_field(report, label), 16)


def _verify_and_extract(ctrtool: Path, cia: Path, dest: Path) -> str:
    """Verify the 7.x-seed scope + protected hashes, then extract regions."""
    report = _run_text(
        [str(ctrtool), f"--seeddb={SEEDDB}", "-v", "-y", "-t", "cia", str(cia)]
    )
    if "Secure (1)" not in report:
        raise SystemExit("CIA content is not 7.x-seed crypto (Secure 1)")
    for integrity in ("Exheader hash", "ExeFS hash", "RomFS hash"):
        if re.search(rf"{re.escape(integrity)}:\s*\(GOOD\)", report) is None:
            raise SystemExit(f"ctrtool {integrity} integrity check failed")
    _run_text(
        [
            str(ctrtool),
            f"--seeddb={SEEDDB}",
            "-t",
            "cia",
            "--exheader",
            str(dest / "exheader.bin"),
            "--plainrgn",
            str(dest / "plain.bin"),
            "--logo",
            str(dest / "logo.bin"),
            "--exefs",
            str(dest / "exefs.bin"),
            "--romfs",
            str(dest / "romfs.bin"),
            str(cia),
        ]
    )
    return report


def main() -> None:
    if len(sys.argv) > 3:
        raise SystemExit(__doc__)
    cia = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else (
        ROOT / "fixtures" / "_local" / "BoxBoxBoy! (USA) (eShop).cia"
    )
    slug = sys.argv[2] if len(sys.argv) > 2 else "boxboxboy"
    if not cia.is_file():
        raise SystemExit(f"retail CIA not found: {cia}")
    if not SEEDDB.is_file():
        raise SystemExit(
            f"seeddb not found: {SEEDDB} (see docs/3DS-KEYED-WORK.md)"
        )

    cia_sha = _sha256(cia)
    ctrtool = _check_ctrtool()
    output = ROOT / "fixtures" / "3ds_ncch_enc_seed" / slug
    reference = output / "reference"

    with tempfile.TemporaryDirectory(prefix="substratum-ncch-seed-") as temp:
        tmp = Path(temp)
        report = _verify_and_extract(ctrtool, cia, tmp)

        output.mkdir(parents=True, exist_ok=True)
        if reference.exists():
            shutil.rmtree(reference)
        reference.mkdir()
        region_meta = {}
        for name, label in (
            ("extendedheader.bin", "exheader"),
            ("plain.bin", "plain"),
            ("logo.bin", "logo"),
            ("exefs.bin", "exefs"),
            ("romfs.bin", "romfs"),
        ):
            src = tmp / f"{label}.bin"
            if src.is_file():
                shutil.copy2(src, reference / name)
                region_meta[name] = _sha256(src)

    title_id = _field(report, "Title id")
    product_code = _field(report, "Product code")
    content_size = _hex(report, "Content size")
    manifest = {
        "format": "3ds-ncch-enc-seed",
        "source": {"name": cia.name, "sha256": cia_sha, "size": cia.stat().st_size},
        "identity": {
            "title_id": title_id,
            "product_code": product_code,
            "crypto": "7.x-seed (Secure 1, KeyY seeded, keyslot 0x25)",
            "content_size": content_size,
        },
        "tool_versions": {
            "ctrtool": vendor_tools.CTRTOOL_BANNER,
            "generator": GENERATOR,
        },
        "oracle": {
            "protected_hashes": (
                "ctrtool -y verifies the NCCH-declared Exheader/ExeFS/RomFS "
                "protected SHA-256 hashes (all GOOD); the runtime normalizer "
                "re-validates them by composing through three_ds_ncch"
            ),
            "two_party_note": (
                "3dstool cannot serve as a second decryptor: it handles "
                "neither the CIA container nor a raw 7.x-seed NCCH slice "
                "(both fail on the encrypted header)"
            ),
        },
        "regions": [
            {"path": name, "sha256": digest}
            for name, digest in sorted(region_meta.items())
        ],
    }
    text = json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    manifest_path = output / "anchor.json"
    manifest_path.write_bytes((text + "\n").encode("ascii"))
    print(f"validated {cia.name}: 7.x-seed, content 0x{content_size:x}")
    print(f"manifest -> {manifest_path}")
    print(f"decrypted references (gitignored) -> {reference}")


if __name__ == "__main__":
    main()
