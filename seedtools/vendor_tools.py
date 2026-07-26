#!/usr/bin/env python3
"""Vendor the pinned differential tools into gitignored tools/ (prep rows
`vendor-chdman` + `vendor-dolphin-tool-or-wit`, NORMALIZERS.md).

Idempotent re-provisioning: binaries stay out of git (tools/ is ignored);
this script + the sha256 pins below + the NORMALIZERS.md rows are the
committed record. Re-running verifies-and-skips when a tool is already
present with the pinned banner.

Tool choices (researched 2026-07-17):
- chdman: extracted from the official MAME 0.288 Windows SFX (a 7z
  archive; never executed) — mamedev publishes SHA256SUMS beside it.
  License: chdman.cpp is BSD-3-Clause, the linked whole is GPL-2.0+.
- wit v3.05a (Wiimms ISO Tools, GPL-2.0) over dolphin-tool: its listing
  carries sizes+offsets (dolphin-tool --list prints bare names), it has a
  real `wit version` command, and the cygwin64 zip is self-contained
  (dolphin-tool needs the VC++ 2022 redistributable).
- ECM/UNECM: the v1.3.1 Windows release asset (GPL-2.0) supplies an
  independent Mode-1 EDC/ECC reconstructor and verifier. The release
  binaries intentionally report v1.3.0; both the asset and executable
  bytes are pinned so that upstream packaging mismatch cannot drift.

First run prints any sha256 marked TOFU (trust-on-first-use) so it can be
pinned into this file; a later run on drifted bytes then fails loudly.
"""

import hashlib
import re
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
DL = TOOLS / "_dl"

MAME_VERSION = "0.288"
MAME_SFX = "mame0288b_x64.exe"
MAME_URL = f"https://github.com/mamedev/mame/releases/download/mame0288/{MAME_SFX}"
MAME_SUMS_URL = "https://github.com/mamedev/mame/releases/download/mame0288/SHA256SUMS"
MAME_SFX_SHA256 = "e4ae20a2359d716fb16824961b1b0fb28d8662ffd1298504edff39d368bb4a55"
CHDMAN_EXE_SHA256 = "1a919f7be4b94993da3fb543539d8affe3a7e64dd3a9f61c20992a1e4eebd9dd"
CHDMAN_BANNER = "chdman - MAME Compressed Hunks of Data (CHD) manager 0.288 (mame0288)"

WIT_VERSION = "v3.05a"
WIT_ZIP = "wit-v3.05a-r8638-cygwin64.zip"
WIT_URL = f"https://wit.wiimm.de/download/{WIT_ZIP}"
WIT_ZIP_SHA256 = "049670558970f0cea2796d68e0ba1e48491474b5708bf12a95ab8a185f4e59c1"
WIT_EXE_SHA256 = "46026c652117628a25882a9c2615844c5054e347ed5144bb78fbf8c8285e3e83"
WIT_BANNER = "wit: Wiimms ISO Tool v3.05a r8638 cygwin64 - Dirk Clemens - 2022-08-27"

# maxcso (prep row `vendor-maxcso`, NORMALIZERS.md row `cso`): the third-party
# CISO author + `--decompress` round-trip anchor for the cso decode-layer unit.
# maxcso is ISC; bundled libs are permissive (zlib/BSD/MIT/Apache) with 7-zip
# deflate under LGPL — vendored locally and only *run* (not linked, not
# committed), same posture as chdman. Upstream publishes no SHA256SUMS, so the
# 7z is TOFU-pinned after first fetch (like wit).
MAXCSO_VERSION = "v1.13.0"
MAXCSO_7Z = "maxcso_v1.13.0_windows.7z"
MAXCSO_URL = (
    f"https://github.com/unknownbrackets/maxcso/releases/download/"
    f"{MAXCSO_VERSION}/{MAXCSO_7Z}"
)
MAXCSO_7Z_SHA256 = "51362619adbb8d219af11321b56b16d4912184203c0127a1b51566c7d151df4d"
MAXCSO_EXE_SHA256 = "05f90b74c4ccdb48f93f9e4c51cc96eb959fd7596d79ba80cf6d8008495fadfb"
MAXCSO_BANNER = "maxcso v1.13.0"

ECM_RELEASE = "v1.3.1"
ECM_ZIP = "ecm_1.3.1_windows_amd64.zip"
ECM_URL = f"https://github.com/kidoz/ecm/releases/download/{ECM_RELEASE}/{ECM_ZIP}"
ECM_ZIP_SHA256 = "c480d5535580cd776cc4b7928cc77d02919b1d1ff19adb45f600a82ff83823a4"
ECM_EXE_SHA256 = "1d5e5eef9bbaa84cd32dd4a4eacd9a6274e66a5a2e09c5804e4b4c6264ec9819"
UNECM_EXE_SHA256 = "eda85f9a7b49dd55d918bce80b862a69650a0f7497b94c89b0fa8f395228d545"
ECM_BANNER = "ECM - Encoder for Error Code Modeler format v1.3.0"
UNECM_BANNER = "UNECM - Decoder for Error Code Modeler format v1.3.0"

DOWNLOAD_TIMEOUT_SECONDS = 60
TOOL_TIMEOUT_SECONDS = 300


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url: str, dest: Path) -> None:
    print(f"fetching {url} -> {dest.name}")
    req = urllib.request.Request(url, headers={"User-Agent": "substratum-vendor/1"})
    with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT_SECONDS) as resp, dest.open("wb") as out:
        while chunk := resp.read(1 << 20):
            out.write(chunk)
    print(f"  {dest.stat().st_size} bytes, sha256 {sha256_of(dest)}")


def run_banner(cmd: list[str]) -> str:
    p = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=TOOL_TIMEOUT_SECONDS,
    )
    return (p.stdout + p.stderr).strip().splitlines()[0] if (p.stdout + p.stderr).strip() else ""


def check_pin(path: Path, expected: str | None, what: str) -> None:
    got = sha256_of(path)
    if expected is None:
        print(f"  TOFU {what}: pin sha256 {got} into this script")
    elif got != expected:
        raise SystemExit(f"{what} sha256 drift: got {got}, pinned {expected}")


def vendor_chdman() -> None:
    exe = TOOLS / "chdman" / "chdman.exe"
    if exe.exists():
        check_pin(exe, CHDMAN_EXE_SHA256, "chdman exe")
        banner = run_banner([str(exe)])
        if banner == CHDMAN_BANNER:
            print(f"chdman already vendored: {banner}")
            return
        raise SystemExit(f"tools/chdman/chdman.exe exists but banner is wrong: {banner!r}")

    DL.mkdir(parents=True, exist_ok=True)
    sums = DL / "SHA256SUMS"
    fetch(MAME_SUMS_URL, sums)
    m = re.search(rf"([0-9a-f]{{64}})\s+\*?{re.escape(MAME_SFX)}", sums.read_text("utf-8"))
    if not m:
        raise SystemExit(f"{MAME_SFX} not in upstream SHA256SUMS")
    upstream_sha = m.group(1)

    sfx = DL / MAME_SFX
    fetch(MAME_URL, sfx)
    if sha256_of(sfx) != upstream_sha:
        raise SystemExit("MAME SFX does not match upstream SHA256SUMS")
    check_pin(sfx, MAME_SFX_SHA256, "mame sfx")

    (TOOLS / "chdman").mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["7z", "e", str(sfx), "chdman.exe", f"-o{TOOLS / 'chdman'}", "-y"],
        capture_output=True, check=True, timeout=TOOL_TIMEOUT_SECONDS,
    )
    check_pin(exe, CHDMAN_EXE_SHA256, "chdman exe")
    banner = run_banner([str(exe)])
    if banner != CHDMAN_BANNER:
        raise SystemExit(f"extracted chdman banner mismatch: {banner!r}")
    print(f"chdman OK: {banner}\n  exe sha256 {sha256_of(exe)}")
    sfx.unlink()  # 82 MB; the pins above re-fetch it if ever needed
    sums.unlink()


def vendor_wit() -> None:
    exe = TOOLS / "wit" / "wit.exe"
    if exe.exists():
        check_pin(exe, WIT_EXE_SHA256, "wit exe")
        banner = run_banner([str(exe), "version"])
        if banner == WIT_BANNER:
            print(f"wit already vendored: {banner}")
            return
        raise SystemExit(f"tools/wit/wit.exe exists but version is wrong: {banner!r}")

    DL.mkdir(parents=True, exist_ok=True)
    zpath = DL / WIT_ZIP
    fetch(WIT_URL, zpath)
    check_pin(zpath, WIT_ZIP_SHA256, "wit zip")

    (TOOLS / "wit").mkdir(parents=True, exist_ok=True)
    kept = 0
    with zipfile.ZipFile(zpath) as z:
        for member in z.namelist():
            p = Path(member)
            if p.parent.name == "bin" and (p.name == "wit.exe" or p.name.endswith(".dll")):
                (TOOLS / "wit" / p.name).write_bytes(z.read(member))
                kept += 1
    if not exe.exists():
        raise SystemExit("wit.exe not found in zip bin/")
    check_pin(exe, WIT_EXE_SHA256, "wit exe")
    banner = run_banner([str(exe), "version"])
    if banner != WIT_BANNER:
        raise SystemExit(f"extracted wit version mismatch: {banner!r}")
    print(f"wit OK ({kept} files): {banner}\n  exe sha256 {sha256_of(exe)}")
    zpath.unlink()


def vendor_maxcso() -> None:
    exe = TOOLS / "maxcso" / "maxcso.exe"
    if exe.exists():
        check_pin(exe, MAXCSO_EXE_SHA256, "maxcso exe")
        banner = run_banner([str(exe), "--version"]) or run_banner([str(exe)])
        if banner == MAXCSO_BANNER:
            print(f"maxcso already vendored: {banner}")
            return
        raise SystemExit(f"tools/maxcso/maxcso.exe exists but banner is unexpected: {banner!r}")

    DL.mkdir(parents=True, exist_ok=True)
    arc = DL / MAXCSO_7Z
    fetch(MAXCSO_URL, arc)
    check_pin(arc, MAXCSO_7Z_SHA256, "maxcso 7z")

    (TOOLS / "maxcso").mkdir(parents=True, exist_ok=True)
    # flat-extract every file (exe + any runtime DLLs) into tools/maxcso/
    subprocess.run(
        ["7z", "e", str(arc), f"-o{TOOLS / 'maxcso'}", "-y"],
        capture_output=True, check=True, timeout=TOOL_TIMEOUT_SECONDS,
    )
    if not exe.exists():
        raise SystemExit("maxcso.exe not found in archive")
    check_pin(exe, MAXCSO_EXE_SHA256, "maxcso exe")
    banner = run_banner([str(exe), "--version"]) or run_banner([str(exe)])
    if banner != MAXCSO_BANNER:
        raise SystemExit(f"extracted maxcso banner mismatch: {banner!r}")
    print(f"maxcso OK: {banner}\n  exe sha256 {sha256_of(exe)}")
    arc.unlink()


def vendor_ecm() -> None:
    tool_dir = TOOLS / "ecm"
    ecm_exe = tool_dir / "ecm.exe"
    unecm_exe = tool_dir / "unecm.exe"
    if ecm_exe.exists() or unecm_exe.exists():
        if not (ecm_exe.exists() and unecm_exe.exists()):
            raise SystemExit("tools/ecm is incomplete; expected ecm.exe and unecm.exe")
        check_pin(ecm_exe, ECM_EXE_SHA256, "ecm exe")
        check_pin(unecm_exe, UNECM_EXE_SHA256, "unecm exe")
        ecm_banner = run_banner([str(ecm_exe)])
        unecm_banner = run_banner([str(unecm_exe)])
        if ecm_banner != ECM_BANNER or unecm_banner != UNECM_BANNER:
            raise SystemExit(
                "tools/ecm banners are unexpected: "
                f"{ecm_banner!r}; {unecm_banner!r}"
            )
        print(f"ecm already vendored: {ecm_banner}; {unecm_banner}")
        return

    DL.mkdir(parents=True, exist_ok=True)
    arc = DL / ECM_ZIP
    fetch(ECM_URL, arc)
    check_pin(arc, ECM_ZIP_SHA256, "ecm zip")

    tool_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(arc) as z:
        members = {Path(info.filename).name: info for info in z.infolist()}
        for name in ("ecm.exe", "unecm.exe"):
            info = members.get(name)
            if info is None or info.is_dir():
                raise SystemExit(f"{name} not found in ECM release zip")
            (tool_dir / name).write_bytes(z.read(info))

    check_pin(ecm_exe, ECM_EXE_SHA256, "ecm exe")
    check_pin(unecm_exe, UNECM_EXE_SHA256, "unecm exe")
    ecm_banner = run_banner([str(ecm_exe)])
    unecm_banner = run_banner([str(unecm_exe)])
    if ecm_banner != ECM_BANNER or unecm_banner != UNECM_BANNER:
        raise SystemExit(
            "extracted ECM banners are unexpected: "
            f"{ecm_banner!r}; {unecm_banner!r}"
        )
    print(
        f"ecm OK: {ecm_banner}; {unecm_banner}\n"
        f"  exe sha256 {sha256_of(ecm_exe)}\n"
        f"  unecm sha256 {sha256_of(unecm_exe)}"
    )
    arc.unlink()


def main() -> None:
    which = set(sys.argv[1:]) or {"chdman", "wit"}
    if "chdman" in which:
        vendor_chdman()
    if "wit" in which:
        vendor_wit()
    if "maxcso" in which:
        vendor_maxcso()
    if "ecm" in which:
        vendor_ecm()


if __name__ == "__main__":
    main()
