"""Nintendo 3DS 7.x-seed encrypted-NCCH decode normalizer.

Decrypts one 7.x-seed-encrypted NCCH (``Crypto Key Secure (1) (KeyY seeded)``,
``ncchflag[3] == 0x01`` with the seed bit) carried inside a **CIA** into a
decrypted ``ByteView`` whose bytes are a NoCrypto NCCH image — the same shape
``three_ds_ncch`` consumes. The caller composes
``normalize(view.source, format="3ds-ncch")`` to walk the regions, exactly as
``3ds-ncch-enc`` does for standard crypto (DESIGN.md section 1).

**Load-bearing difference from standard crypto:** the 7.x-seed variant
encrypts the NCCH *header itself* — the magic at 0x100 is ciphertext, not
plaintext. Two consequences make this a separate module, not a widening of
``three_ds_ncch_enc``:

1. The normalizer consumes a **whole CIA**, not a raw NCCH slice. ctrtool
   cannot decrypt a raw 7.x-seed NCCH slice in isolation ("NcchHeader is
   corrupted") — it needs the CIA's ticket to decrypt the header first.
   Proven: raw-slice decrypt fails; whole-CIA decrypt succeeds.
2. ctrtool exposes the decrypted content *regions* but not the decrypted NCCH
   *header*, so this module reconstructs the header (region table + computed
   protected hashes + NoCrypto flag) from ctrtool's parsed report.

Decryption delegates to the vendored ctrtool **v1.3.0** (7.x keyslot `0x25`
compiled in) plus the operator-supplied **seeddb** (named by
``SUBSTRATUM_CTRTOOL_SEEDDB``), mirroring the ``chd``→chdman and
``wii-partition`` keyed-work precedents.

The independent correctness anchor is the NCCH-declared protected SHA-256
hashes, validated when the decrypted ``ByteView`` composes through
``three_ds_ncch`` — a wrong decrypt fails them. (3dstool cannot serve as a
second decryptor here: it does not handle the CIA container or decrypt a raw
7.x-seed slice.)

Runtime is stdlib-only per DESIGN.md section 4.
"""

from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from substratum.contract import ByteSource, ByteView, FileSource
from substratum.formats._spool import TempFileSource

__all__ = ["sniff", "normalize_3ds_ncch_enc_seed"]

_HEADER_SIZE = 0x200
_MAGIC_OFFSET = 0x100
_NCCH_MAGIC = b"NCCH"
_ACCESS_DESCRIPTOR_SIZE = 0x400
_NO_ENCRYPTION = 1 << 2

# ctrtool resolution (same order as chd / three_ds_ncch_enc).
_CTRTOOL_REL = Path("tools") / "ctrtool" / "ctrtool.exe"
_CTRTOOL_ENV = "SUBSTRATUM_CTRTOOL"
_SEEDDB_ENV = "SUBSTRATUM_CTRTOOL_SEEDDB"
_CTRTOOL_TIMEOUT_SECONDS = 300

# NCCH header field offsets (little-endian), used to reconstruct the header.
_CONTENT_SIZE_UNITS_OFFSET = 0x104
_FORMAT_VERSION_OFFSET = 0x112
_BLOCK_SIZE_LOG_OFFSET = 0x18E
_OTHER_FLAGS_OFFSET = 0x18F
_EXHEADER_SIZE_OFFSET = 0x180
_PLAIN_FIELD = 0x190
_LOGO_FIELD = 0x198
_EXEFS_FIELD = 0x1A0
_ROMFS_FIELD = 0x1B0
_EXHEADER_HASH_OFFSET = 0x160  # 0x20 bytes
_LOGO_HASH_OFFSET = 0x130  # 0x20 bytes
_EXEFS_HASH_OFFSET = 0x1C0  # 0x20 bytes
_ROMFS_HASH_OFFSET = 0x1E0  # 0x20 bytes


# Same owned-mkdtemp shape as `chd.py` / `three_ds_ncch_enc.py`; aliased to the
# shared `_spool.TempFileSource` under this unit's historical private name.
_TempFileSource = TempFileSource


def _ctrtool_exe() -> Path:
    """Resolve ctrtool (same order as chd / three_ds_ncch_enc)."""
    override = os.environ.get(_CTRTOOL_ENV)
    if override is not None:
        if not override.strip():
            raise FileNotFoundError(f"{_CTRTOOL_ENV} is set but empty")
        exe = Path(override).expanduser()
        if exe.is_file():
            return exe
        raise FileNotFoundError(
            f"{_CTRTOOL_ENV} points to a missing file: {exe}"
        )
    on_path = shutil.which("ctrtool")
    if on_path is not None:
        return Path(on_path)
    root = Path(__file__).resolve().parent.parent.parent
    repo_exe = root / _CTRTOOL_REL
    if repo_exe.is_file():
        return repo_exe
    raise FileNotFoundError(
        "ctrtool not found; set SUBSTRATUM_CTRTOOL to ctrtool.exe, "
        "install ctrtool on PATH, or re-vendor a source checkout with "
        "seedtools/vendor_tools.py ctrtool"
    )


def _load_seeddb() -> Path:
    """Resolve the operator-supplied seeddb (presence-only, never contents).

    Mirrors the Wii common-key discipline (docs/WII-KEYED-WORK.md): the path
    is named by ``SUBSTRATUM_CTRTOOL_SEEDDB``; code reports only whether the
    file exists, never its bytes or digest.
    """
    raw = os.environ.get(_SEEDDB_ENV)
    if not raw:
        raise ValueError(
            f"{_SEEDDB_ENV} is not set; supply the seeddb path "
            "(see docs/3DS-KEYED-WORK.md)"
        )
    path = Path(raw)
    if not path.is_file():
        raise ValueError(
            f"{_SEEDDB_ENV} points to a missing file "
            "(see docs/3DS-KEYED-WORK.md)"
        )
    return path


def _is_cia(source: ByteSource) -> bool:
    """A CIA has a fixed 0x2020 CiaHeader with Normal type / Cia version."""
    if source.size() < 0x40:
        return False
    header = source.read_at(0, 0x40)
    if struct.unpack_from("<I", header, 0x00)[0] != 0x2020:
        return False
    archive_type = struct.unpack_from("<H", header, 0x04)[0]
    format_version = struct.unpack_from("<H", header, 0x06)[0]
    content_size = struct.unpack_from("<I", header, 0x18)[0]
    return archive_type == 0 and format_version == 0 and content_size > 0


def _content_offset(cia: Path) -> int:
    """Compute the CIA content-section offset via 64-byte per-section alignment."""
    def align64(x: int) -> int:
        return (x + 0x3F) // 0x40 * 0x40

    with cia.open("rb") as fh:
        header = fh.read(0x20)
    header_size = struct.unpack_from("<I", header, 0x00)[0]
    cert_size = struct.unpack_from("<I", header, 0x08)[0]
    tik_size = struct.unpack_from("<I", header, 0x0C)[0]
    tmd_size = struct.unpack_from("<I", header, 0x10)[0]
    return align64(align64(align64(align64(header_size) + cert_size) + tik_size) + tmd_size)


def sniff(source: ByteSource) -> bool:
    """True for a CIA whose NCCH content header is encrypted (7.x-seed shape).

    The 7.x-seed variant encrypts the NCCH header, so the magic at the
    content offset is ciphertext (not ``NCCH``). This sniffer detects that:
    a valid CIA whose content's NCCH magic is NOT plaintext. A standard-crypto
    CIA (plaintext header) is left for ``3ds-ncch-enc``.
    """
    if not _is_cia(source):
        return False
    # Resolve a path to read the content offset (sniff only gets a ByteSource).
    if isinstance(source, FileSource):
        cia_path = source.path
    else:
        # Non-file CIA sources are rare for sniff; stage to test membership.
        return False
    try:
        content_off = _content_offset(cia_path)
    except (OSError, ValueError):
        return False
    if source.size() < content_off + _MAGIC_OFFSET + 4:
        return False
    magic = source.read_at(content_off + _MAGIC_OFFSET, 4)
    return magic != _NCCH_MAGIC


def _run_text(command: list[str]) -> str:
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=_CTRTOOL_TIMEOUT_SECONDS,
    )
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise RuntimeError(f"ctrtool failed: {command[0]}\n{output}")
    return output


def _field(report: str, label: str) -> str:
    # ctrtool indents nested fields with tree prefixes (`|- `, `- `, `> `);
    # match the label anywhere a line carries it as `Label:` followed by a value.
    m = re.search(rf"(?:^|\s){re.escape(label)}:\s*(.+)$", report, re.M)
    if m is None:
        raise ValueError(f"ctrtool report omitted {label!r}")
    return m.group(1).strip()


def _hex_field(report: str, label: str) -> int:
    return int(_field(report, label), 16)


def _hash_field(report: str, label: str) -> bytes:
    return bytes.fromhex(_field(report, label))


def _decrypt_regions(
    ctrtool: Path, seeddb: Path, cia: Path, dest: Path
) -> dict[str, Path]:
    """Extract every decrypted NCCH region via ctrtool (default mode decrypts)."""
    paths = {
        "exheader": dest / "exheader.bin",
        "plain": dest / "plain.bin",
        "logo": dest / "logo.bin",
        "exefs": dest / "exefs.bin",
        "romfs": dest / "romfs.bin",
    }
    _run_text(
        [
            str(ctrtool),
            f"--seeddb={seeddb}",
            "-t",
            "cia",
            "--exheader",
            str(paths["exheader"]),
            "--plainrgn",
            str(paths["plain"]),
            "--logo",
            str(paths["logo"]),
            "--exefs",
            str(paths["exefs"]),
            "--romfs",
            str(paths["romfs"]),
            str(cia),
        ]
    )
    return paths


def _assemble_nocrypto_ncch(
    report: str, regions: dict[str, Path], dest: Path
) -> Path:
    """Reconstruct a NoCrypto NCCH image from ctrtool's report + regions.

    ctrtool exposes the decrypted regions but not the decrypted NCCH header,
    so this rebuilds the 0x200 header (magic, content size, format version,
    block-size log, region table, protected hashes, NoCrypto flag) from the
    parsed report, then places each decrypted region at its declared offset.
    """
    content_size = _hex_field(report, "Content size")
    block_size = _hex_field(report, "BlockSize") or 0x200
    block_size_log = block_size.bit_length() - 10  # block = 1 << (log + 9)
    exheader_size = _hex_field(report, "Exheader size")

    image = bytearray(content_size)
    header = bytearray(_HEADER_SIZE)
    header[_MAGIC_OFFSET : _MAGIC_OFFSET + 4] = _NCCH_MAGIC
    struct.pack_into("<I", header, _CONTENT_SIZE_UNITS_OFFSET, content_size // block_size)
    struct.pack_into("<H", header, _FORMAT_VERSION_OFFSET, 2)
    header[_BLOCK_SIZE_LOG_OFFSET] = block_size_log
    header[_OTHER_FLAGS_OFFSET] = _NO_ENCRYPTION  # decrypted form
    struct.pack_into("<I", header, _EXHEADER_SIZE_OFFSET, exheader_size)

    # Protected hashes (NCCH spec) — read from ctrtool's report.
    header[_EXHEADER_HASH_OFFSET : _EXHEADER_HASH_OFFSET + 0x20] = _hash_field(
        report, "Exheader hash"
    )
    # Logo hash + region (may be absent).
    try:
        logo_off = _hex_field(report, "Logo offset")
        logo_size = _hex_field(report, "Logo size")
        header[_LOGO_HASH_OFFSET : _LOGO_HASH_OFFSET + 0x20] = _hash_field(
            report, "Logo hash"
        )
        if logo_off and logo_size:
            struct.pack_into("<II", header, _LOGO_FIELD, logo_off // block_size, logo_size // block_size)
    except ValueError:
        logo_off = logo_size = 0

    # ExeFS / RomFS region table + protected hashes.
    for label, field, hash_off in (
        ("Plain region", _PLAIN_FIELD, None),
        ("ExeFS", _EXEFS_FIELD, _EXEFS_HASH_OFFSET),
        ("RomFS", _ROMFS_FIELD, _ROMFS_HASH_OFFSET),
    ):
        off = _hex_field(report, f"{label} offset")
        size = _hex_field(report, f"{label} size")
        struct.pack_into("<II", header, field, off // block_size, size // block_size)
        if hash_off is not None:
            header[hash_off : hash_off + 0x20] = _hash_field(report, f"{label} hash")

    image[0:_HEADER_SIZE] = header

    # Place the decrypted regions at their declared byte offsets.
    def place(name: str, off: int) -> None:
        path = regions[name]
        if path.is_file():
            data = path.read_bytes()
            image[off : off + len(data)] = data

    place("exheader", _HEADER_SIZE)  # exheader region = 0x200..(exheader+access)
    if logo_off and logo_size and regions["logo"].is_file():
        place("logo", logo_off)
    place("plain", _hex_field(report, "Plain region offset"))
    place("exefs", _hex_field(report, "ExeFS offset"))
    place("romfs", _hex_field(report, "RomFS offset"))

    out = dest / "decrypted.ncch"
    out.write_bytes(bytes(image))
    return out


def normalize_3ds_ncch_enc_seed(source) -> ByteView:
    """Decrypt one 7.x-seed-encrypted NCCH (inside a CIA) into a NoCrypto ByteView."""
    src = source if isinstance(source, ByteSource) else FileSource(source)
    if not _is_cia(src):
        raise ValueError("not a CIA container (3ds-ncch-enc-seed consumes a whole CIA)")

    ctrtool = _ctrtool_exe()
    seeddb = _load_seeddb()
    cia_path = src.path if isinstance(src, FileSource) else _stage_cia(src)

    tmp_dir = Path(tempfile.mkdtemp(prefix="substratum-ncch-seed-"))
    try:
        # Parse ctrtool's report for the region table + protected hashes.
        report = _run_text(
            [str(ctrtool), f"--seeddb={seeddb}", "-v", "-t", "cia", str(cia_path)]
        )
        # Confirm the 7.x-seed variant scope.
        if "Secure (1)" not in report:
            raise ValueError(
                "CIA content is not 7.x-seed crypto (Secure 1); "
                "use the matching encrypted-NCCH normalizer"
            )
        regions = _decrypt_regions(ctrtool, seeddb, cia_path, tmp_dir)
        decrypted = _assemble_nocrypto_ncch(report, regions, tmp_dir)
        return ByteView(
            source=_TempFileSource(decrypted, tmp_dir), format="3ds-ncch-enc-seed"
        )
    except BaseException:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
    finally:
        if not isinstance(src, FileSource):
            Path(cia_path).unlink(missing_ok=True)


def _stage_cia(src: ByteSource) -> Path:
    """Stage a non-file CIA source to a temp path (ctrtool requires a path)."""
    tmp = tempfile.NamedTemporaryFile(suffix=".cia", delete=False)
    try:
        total = src.size()
        pos = 0
        while pos < total:
            chunk = src.read_at(pos, min(1 << 20, total - pos))
            tmp.write(chunk)
            pos += len(chunk)
        tmp.flush()
        return Path(tmp.name)
    finally:
        tmp.close()
