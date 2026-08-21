#!/usr/bin/env python3
"""Vendor the pinned differential tools into gitignored tools/ (prep rows
recorded in NORMALIZERS.md).

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
- ctrtool + 3dstool: independently maintained 3DS readers used together
  for CCI/NCSD and decrypted NCCH listing/extraction. Only the executables
  are retained; no external key file is downloaded or vendored.

First run prints any sha256 marked TOFU (trust-on-first-use) so it can be
pinned into this file; a later run on drifted bytes then fails loudly.
"""

import hashlib
import re
import shutil
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

CTRTOOL_VERSION = "v1.3.0"
CTRTOOL_ZIP = "ctrtool-v1.3.0-win_x64.zip"
CTRTOOL_URL = (
    "https://github.com/3DSGuy/Project_CTR/releases/download/"
    f"ctrtool-{CTRTOOL_VERSION}/{CTRTOOL_ZIP}"
)
CTRTOOL_ZIP_SHA256 = "8031dff3be72d0adb250fae1f969f27627e12a89ebc6dd074a15a75f87ddc949"
CTRTOOL_EXE_SHA256 = "79021f283b2199950eb22cf3c459806b9c8aaaf68f65c80100107d3454a1c224"
CTRTOOL_BANNER = "CTRTool v1.3.0 (C) jakcron"

THREEDSTOOL_VERSION = "v1.2.6"
THREEDSTOOL_ZIP = "3dstool.zip"
THREEDSTOOL_URL = (
    "https://github.com/dnasdw/3dstool/releases/download/"
    f"{THREEDSTOOL_VERSION}/{THREEDSTOOL_ZIP}"
)
THREEDSTOOL_ZIP_SHA256 = "481e20f445eb2f0f506d0d88cd750385bc8377670d681d6f66f584a176027806"
THREEDSTOOL_EXE_SHA256 = "967fd5ec6476df1fa6a01da0df5a1fea339aa488c10be218d38e07f4b8143b7e"
THREEDSTOOL_BANNER = "3dstool 1.2.6 by dnasdw"

DOLPHIN_VERSION = "2606a"
DOLPHIN_7Z = "dolphin-2606a-x64.7z"
DOLPHIN_URL = f"https://dl.dolphin-emu.org/releases/{DOLPHIN_VERSION}/{DOLPHIN_7Z}"
DOLPHIN_7Z_SHA256 = "4c58045f9821cb63913f4df08ea86ece3cdda9f9e646154516000fa1547e0c37"
DOLPHIN_TOOL_EXE_SHA256 = "98f0a7d2e711eeb53a3504d453eb970f4178e48dcb4c745e3d8fa24d8d90a6bc"
DOLPHIN_TOOL_BANNER_FRAGMENT = "dolphin-tool"  # `dolphin-tool convert --help` lists supported commands

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


def run_output(cmd: list[str]) -> str:
    p = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=TOOL_TIMEOUT_SECONDS,
    )
    return (p.stdout + p.stderr).strip()


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


def _extract_named_executable(archive: Path, executable: str, destination: Path) -> None:
    with zipfile.ZipFile(archive) as z:
        matches = [
            info
            for info in z.infolist()
            if not info.is_dir() and Path(info.filename).name.lower() == executable.lower()
        ]
        if len(matches) != 1:
            raise SystemExit(
                f"expected exactly one {executable} in {archive.name}, found {len(matches)}"
            )
        destination.write_bytes(z.read(matches[0]))


def vendor_ctrtool() -> None:
    tool_dir = TOOLS / "ctrtool"
    exe = tool_dir / "ctrtool.exe"
    if exe.exists():
        check_pin(exe, CTRTOOL_EXE_SHA256, "ctrtool exe")
        output = run_output([str(exe), "--help"])
        if CTRTOOL_BANNER not in output:
            raise SystemExit(f"tools/ctrtool/ctrtool.exe banner is unexpected: {output!r}")
        print(f"ctrtool already vendored: {CTRTOOL_BANNER}")
        return

    DL.mkdir(parents=True, exist_ok=True)
    archive = DL / CTRTOOL_ZIP
    fetch(CTRTOOL_URL, archive)
    check_pin(archive, CTRTOOL_ZIP_SHA256, "ctrtool zip")

    tool_dir.mkdir(parents=True, exist_ok=True)
    _extract_named_executable(archive, "ctrtool.exe", exe)
    check_pin(exe, CTRTOOL_EXE_SHA256, "ctrtool exe")
    output = run_output([str(exe), "--help"])
    if CTRTOOL_BANNER not in output:
        raise SystemExit(f"extracted ctrtool banner mismatch: {output!r}")
    print(f"ctrtool OK: {CTRTOOL_BANNER}\n  exe sha256 {sha256_of(exe)}")
    archive.unlink()


def vendor_3dstool() -> None:
    tool_dir = TOOLS / "3dstool"
    exe = tool_dir / "3dstool.exe"
    if exe.exists():
        check_pin(exe, THREEDSTOOL_EXE_SHA256, "3dstool exe")
        banner = run_banner([str(exe), "--help"])
        if banner != THREEDSTOOL_BANNER:
            raise SystemExit(f"tools/3dstool/3dstool.exe banner is unexpected: {banner!r}")
        print(f"3dstool already vendored: {banner}")
        return

    DL.mkdir(parents=True, exist_ok=True)
    archive = DL / THREEDSTOOL_ZIP
    fetch(THREEDSTOOL_URL, archive)
    check_pin(archive, THREEDSTOOL_ZIP_SHA256, "3dstool zip")

    tool_dir.mkdir(parents=True, exist_ok=True)
    _extract_named_executable(archive, "3dstool.exe", exe)
    check_pin(exe, THREEDSTOOL_EXE_SHA256, "3dstool exe")
    banner = run_banner([str(exe), "--help"])
    if banner != THREEDSTOOL_BANNER:
        raise SystemExit(f"extracted 3dstool banner mismatch: {banner!r}")
    print(f"3dstool OK: {banner}\n  exe sha256 {sha256_of(exe)}")
    archive.unlink()


def vendor_dolphin_tool() -> None:
    tool_dir = TOOLS / "dolphin-tool"
    exe = tool_dir / "DolphinTool.exe"
    if exe.exists():
        check_pin(exe, DOLPHIN_TOOL_EXE_SHA256, "dolphin-tool exe")
        banner = run_output([str(exe), "convert", "--help"])
        if DOLPHIN_TOOL_BANNER_FRAGMENT not in banner:
            raise SystemExit(f"tools/dolphin-tool/DolphinTool.exe banner is unexpected: {banner!r}")
        print(f"dolphin-tool already vendored: {DOLPHIN_VERSION} ({exe.name})")
        return

    DL.mkdir(parents=True, exist_ok=True)
    archive = DL / DOLPHIN_7Z
    fetch(DOLPHIN_URL, archive)
    check_pin(archive, DOLPHIN_7Z_SHA256, "dolphin 7z")

    tool_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["7z", "e", str(archive), r"Dolphin-x64\DolphinTool.exe", f"-o{tool_dir}", "-y"],
        capture_output=True,
        check=True,
        timeout=TOOL_TIMEOUT_SECONDS,
    )
    # normalize casing to the expected name (7z preserves the source casing)
    extracted = tool_dir / "DolphinTool.exe"
    if not extracted.exists():
        # fallback: case-insensitive search
        for candidate in tool_dir.iterdir():
            if candidate.name.lower() == "dolphintool.exe":
                candidate.rename(extracted)
                break
    if not exe.exists():
        raise SystemExit("DolphinTool.exe not found after extraction")
    check_pin(exe, DOLPHIN_TOOL_EXE_SHA256, "dolphin-tool exe")
    banner = run_output([str(exe), "convert", "--help"])
    if DOLPHIN_TOOL_BANNER_FRAGMENT not in banner:
        raise SystemExit(f"extracted dolphin-tool banner mismatch: {banner!r}")
    print(f"dolphin-tool OK: {DOLPHIN_VERSION} ({exe.name})\n  exe sha256 {sha256_of(exe)}")
    archive.unlink()


# NKit 1.4 (row `nkit`): the last public NKit release (NKit 2 is
# Discord-distributed with no public source -- recorded in the row). The
# gbatemp download is referer/UA-gated; the sha256 below is the AUR
# package's independent pin (aur.archlinux.org/packages/nkit), so two
# parties agree on the bytes. MIT license (NKitv1 source). The config's
# WaitForKeyAfterProcessing is flipped to false so the CLI exits without
# console input; everything else ships as-is.
NKIT_VERSION = "1.4"
NKIT_URL = "https://gbatemp.net/download/nkit.36157/download?version=36607"
NKIT_REFERER = "https://gbatemp.net/download/nkit.36157/"
NKIT_ZIP_SHA256 = "e600b0a2dbacf784779ce33b01259f197c5f8cfc7135f1831160d3f98bb431c6"
# Executable-level pin, same discipline as every other vendored tool. The zip
# pin alone only covers the fetch path; without this the "already vendored"
# fast path below accepted whatever ConvertToISO.exe happened to be on disk —
# and this is the one tool whose source is a referer-gated forum download.
# AGENTS.md section 5: a re-run on a drifted binary must fail loudly.
NKIT_EXE_SHA256 = "6e83642de8a8bb8143a82c60061e7df4d769179ea17628842f4f19c3aab17bc8"


def vendor_nkit() -> None:
    exe = TOOLS / "nkit" / "ConvertToISO.exe"
    if exe.is_file():
        check_pin(exe, NKIT_EXE_SHA256, "nkit exe")
        print("nkit already vendored (tools/nkit/ConvertToISO.exe present)")
        return
    zpath = DL / "nkit-1.4.zip"
    if not (zpath.is_file() and sha256_of(zpath) == NKIT_ZIP_SHA256):
        print(f"fetching {NKIT_URL} -> {zpath.name} (referer-gated)")
        req = urllib.request.Request(
            NKIT_URL,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Referer": NKIT_REFERER,
            },
        )
        with urllib.request.urlopen(
            req, timeout=DOWNLOAD_TIMEOUT_SECONDS
        ) as resp, zpath.open("wb") as out:
            while chunk := resp.read(1 << 20):
                out.write(chunk)
    check_pin(zpath, NKIT_ZIP_SHA256, "nkit zip")
    dest = TOOLS / "nkit"
    if dest.exists():
        shutil.rmtree(dest)
    with zipfile.ZipFile(zpath) as zf:
        zf.extractall(dest)
    if not exe.is_file():
        raise SystemExit("ConvertToISO.exe not found after extraction")
    check_pin(exe, NKIT_EXE_SHA256, "nkit exe")
    # non-interactive CLI: the shipped config waits for a key on exit
    cfg = dest / "NKit.dll.config"
    s = cfg.read_text(encoding="utf-8-sig")
    s2 = s.replace(
        'WaitForKeyAfterProcessing" value="true"',
        'WaitForKeyAfterProcessing" value="false"',
    )
    if s2 == s:
        raise SystemExit("WaitForKeyAfterProcessing patch failed (key moved?)")
    cfg.write_text(s2, encoding="utf-8", newline="")
    print(f"nkit OK: {NKIT_VERSION} (ConvertToISO.exe)")
    print(f"  zip sha256 {NKIT_ZIP_SHA256}")
    print(f"  exe sha256 {NKIT_EXE_SHA256}")


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
    if "ctrtool" in which or "3ds" in which:
        vendor_ctrtool()
    if "3dstool" in which or "3ds" in which:
        vendor_3dstool()
    if "dolphin-tool" in which or "rvz" in which:
        vendor_dolphin_tool()
    if "nkit" in which:
        vendor_nkit()


if __name__ == "__main__":
    main()
