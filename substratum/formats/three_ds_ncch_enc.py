"""Nintendo 3DS encrypted-NCCH decode normalizer (standard crypto only).

Decrypts one standard-encrypted NCCH into a decrypted ``ByteView`` whose bytes
are a NoCrypto NCCH image — the same shape ``three_ds_ncch`` consumes. Per
DESIGN.md §1 this is a decode layer only: it returns a ``ByteView`` and never
recurses into the inner region table. The caller composes
``normalize(view.source, format="3ds-ncch")`` to walk the regions, exactly as
``chd``→``iso9660`` composes (DESIGN.md §1).

Decryption delegates to the vendored ctrtool **v1.3.0**, which carries retail
AES keys compiled in and decrypts standard-encrypted NCCH with no external key
material (docs/3DS-KEYED-WORK.md). This mirrors the ``chd``→chdman precedent
and is consistent with DESIGN.md §4: "runtime stdlib-only" means no pip/runtime
dependencies, not no subprocess.

Scope: the no-seed encrypted variants ``ncchflag[3] in {0x00, 0x01}`` —
standard crypto (keyslot 0x2C) and plain-7.x secured crypto (keyslot 0x25).
Both carry a plaintext NCCH header and decrypt via the same ctrtool command
with no seeddb (docs/3DS-KEYED-WORK.md § Plain-7.x two-party finding). Seed
crypto (the 0x20 flag bit), New3DS 9.3 (0x0A), and New3DS 9.6 (0x0B) are
refused; 7.x-seed is handled by the separate ``three_ds_ncch_enc_seed`` module
(which consumes a whole CIA because it encrypts the header itself), and the
seeded 9.6 path additionally needs ``--seeddb=``. CIA container parsing is a
separate unit — this layer consumes the NCCH *content* slice.

Runtime is stdlib-only per DESIGN.md §4.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path

from substratum.contract import ByteSource, ByteView, FileSource
from substratum.formats._spool import TempFileSource

__all__ = ["sniff", "normalize_3ds_ncch_enc"]

_HEADER_SIZE = 0x200
_MAGIC_OFFSET = 0x100
_NCCH_MAGIC = b"NCCH"

# Header fields shared with three_ds_ncch (duplicated intentionally so this
# decode layer is independently dispatchable, not coupled to its sibling).
_FORMAT_VERSION_OFFSET = 0x112
_BLOCK_SIZE_LOG_OFFSET = 0x18E
_OTHER_FLAGS_OFFSET = 0x18F
_NO_ENCRYPTION = 1 << 2
_SEEDED_AES_KEY_Y = 1 << 5
_NCCH_FLAGS_OFFSET = 0x188
# ncchflag[3] values that decrypt with a plaintext header and no seeddb:
# 0x00 = standard crypto (keyslot 0x2C), 0x01 = plain-7.x secured (0x25).
# 7.x-seed is a separate module (header-encrypted, CIA-consuming); 9.3/9.6 are
# out of scope.
_NO_SEED_CRYPTO_FLAGS = frozenset({0x00, 0x01})

_CONTENT_SIZE_UNITS_OFFSET = 0x104
_EXHEADER_SIZE_OFFSET = 0x180
_ACCESS_DESCRIPTOR_SIZE = 0x400

# Region table fields (offset, size[, protected-Units]) in NCCH-block units.
_PLAIN_FIELD = 0x190
_EXEFS_FIELD = 0x1A0
_ROMFS_FIELD = 0x1B0
_EXHEADER_REGION_OFFSET = _HEADER_SIZE  # 0x200

_CTRTOOL_REL = Path("tools") / "ctrtool" / "ctrtool.exe"
_CTRTOOL_ENV = "SUBSTRATUM_CTRTOOL"
_CTRTOOL_TIMEOUT_SECONDS = 300


# The assembled decrypted NCCH lives in a mkdtemp directory this source owns.
# That is exactly `_spool.TempFileSource`; aliased under this unit's historical
# private name so the shape lives in one place (same pattern as `chd.py` and
# `rvz.py`).
_TempFileSource = TempFileSource


def _repo_ctrtool_candidate() -> Path:
    root = Path(__file__).resolve().parent.parent.parent
    return root / _CTRTOOL_REL


def _ctrtool_exe() -> Path:
    """Resolve ctrtool for wheels and source checkouts in explicit order."""
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

    repo_exe = _repo_ctrtool_candidate()
    if repo_exe.is_file():
        return repo_exe

    raise FileNotFoundError(
        "ctrtool not found; set SUBSTRATUM_CTRTOOL to ctrtool.exe, "
        "install ctrtool on PATH, or re-vendor a source checkout with "
        "seedtools/vendor_tools.py ctrtool"
    )


def _validate_encrypted_ncch_header(header: bytes, source_size: int) -> int:
    """Validate the NCCH header and the standard-encrypted scope; return the
    NCCH block size in bytes."""
    if header[_MAGIC_OFFSET : _MAGIC_OFFSET + 4] != _NCCH_MAGIC:
        raise ValueError("not a 3DS NCCH image (missing NCCH magic)")

    format_version = struct.unpack_from("<H", header, _FORMAT_VERSION_OFFSET)[0]
    if format_version == 1:
        raise ValueError("NCCH prototype format version 1 is outside scope")
    if format_version not in {0, 2}:
        raise ValueError(f"unsupported NCCH format version {format_version}")

    block_size_log = header[_BLOCK_SIZE_LOG_OFFSET]
    if block_size_log > 31:
        raise ValueError(f"invalid NCCH block-size log {block_size_log}")
    block_size = 1 << (block_size_log + 9)

    content_units = struct.unpack_from("<I", header, _CONTENT_SIZE_UNITS_OFFSET)[0]
    declared_size = content_units * block_size
    if declared_size != source_size:
        raise ValueError(
            f"declared NCCH content size {declared_size} does not match "
            f"source size {source_size}"
        )

    crypto_method = header[_NCCH_FLAGS_OFFSET + 3]
    if crypto_method not in _NO_SEED_CRYPTO_FLAGS:
        raise ValueError(
            f"NCCH crypto method 0x{crypto_method:02x} is outside no-seed scope; "
            "only standard (0x00) and plain-7.x (0x01) are supported here"
        )

    other_flags = header[_OTHER_FLAGS_OFFSET]
    if other_flags & _NO_ENCRYPTION:
        raise ValueError(
            "NCCH is already decrypted (NoCrypto); use the 3ds-ncch normalizer"
        )
    if other_flags & _SEEDED_AES_KEY_Y:
        raise ValueError("seed-encrypted NCCH is outside standard-crypto scope")
    return block_size


def _region_fields(header: bytes, field_offset: int, block_size: int):
    """Return (byte_offset, byte_size) for a region table entry, or None when
    the region is absent."""
    offset_units, size_units = struct.unpack_from("<II", header, field_offset)
    if offset_units == 0 and size_units == 0:
        return None
    if offset_units == 0 or size_units == 0:
        raise ValueError(
            f"half-empty region at field 0x{field_offset:x}: "
            f"offset={offset_units}, size={size_units}"
        )
    return offset_units * block_size, size_units * block_size


def _ctrtool_decrypt_region(
    ctrtool: Path,
    ncch_path: Path,
    flag: str,
    destination: Path,
) -> None:
    """Extract one decrypted region via ctrtool (default mode decrypts)."""
    result = subprocess.run(
        [str(ctrtool), "-t", "ncch", flag, str(destination), str(ncch_path)],
        capture_output=True,
        timeout=_CTRTOOL_TIMEOUT_SECONDS,
    )
    if result.returncode != 0 or not destination.is_file():
        stderr = result.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(
            f"ctrtool failed to extract region with {flag}"
            + (f": {stderr}" if stderr else "")
        )


def _stage_source(src: ByteSource) -> Path:
    """Return a filesystem path for ``src``, staging to a temp .ncch when it
    is not already a file (ctrtool requires a path)."""
    if isinstance(src, FileSource):
        return src.path
    tmp = tempfile.NamedTemporaryFile(suffix=".ncch", delete=False)
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


def sniff(source: ByteSource) -> bool:
    """True for an encrypted no-seed NCCH (standard or plain-7.x crypto).

    The NCCH magic at 0x100 is plaintext for both standard crypto and plain-7.x
    (the header is not encrypted — unlike 7.x-seed, which encrypts the header
    itself and is dispatched by ``three_ds_ncch_enc_seed``); the flags byte
    distinguishes encrypted from the decrypted form ``three_ds_ncch`` handles.
    This sniffer is registered *before* ``3ds-ncch`` so encrypted content
    dispatches here.
    """
    if source.size() < _MAGIC_OFFSET + 4:
        return False
    if source.read_at(_MAGIC_OFFSET, 4) != _NCCH_MAGIC:
        return False
    flags = source.read_at(_OTHER_FLAGS_OFFSET, 1)
    if flags[0] & _NO_ENCRYPTION:
        return False  # already decrypted -> 3ds-ncch's domain
    if flags[0] & _SEEDED_AES_KEY_Y:
        return False  # seed crypto -> three_ds_ncch_enc_seed's domain
    crypto = source.read_at(_NCCH_FLAGS_OFFSET + 3, 1)
    return crypto[0] in _NO_SEED_CRYPTO_FLAGS


def normalize_3ds_ncch_enc(source) -> ByteView:
    """Decrypt one no-seed encrypted NCCH into a NoCrypto ``ByteView``.

    Accepts standard crypto (``ncchflag[3] == 0x00``) and plain-7.x secured
    crypto (``0x01``); both carry a plaintext header and decrypt via the same
    ctrtool command with no seeddb. Accepts a path (str/Path) or a ByteSource
    over an encrypted NCCH. The returned ByteView's source is a temp file
    holding an assembled NoCrypto NCCH image (the on-media header with
    plaintext regions, decrypted ExeFS / RomFS / extended-header placed at
    their declared offsets, and the NoCrypto flag set). ``three_ds_ncch``
    consumes that image directly.
    """
    src = source if isinstance(source, ByteSource) else FileSource(source)
    source_size = src.size()
    if source_size < _HEADER_SIZE:
        raise ValueError("source too small to contain a 3DS NCCH header")
    header = bytearray(src.read_at(0, _HEADER_SIZE))
    block_size = _validate_encrypted_ncch_header(header, source_size)

    exheader_size = struct.unpack_from("<I", header, _EXHEADER_SIZE_OFFSET)[0]
    if exheader_size not in {0, 0x400}:
        raise ValueError(
            f"invalid extended-header size {exheader_size:#x}"
        )
    plain = _region_fields(header, _PLAIN_FIELD, block_size)
    exefs = _region_fields(header, _EXEFS_FIELD, block_size)
    romfs = _region_fields(header, _ROMFS_FIELD, block_size)

    ctrtool = _ctrtool_exe()

    # Stage the encrypted source to a path ctrtool can read.
    ncch_path = _stage_source(src)
    staged_temp = None if isinstance(src, FileSource) else ncch_path

    tmp_dir = Path(tempfile.mkdtemp(prefix="substratum-ncch-enc-"))
    try:
        # Start from the on-media image: header + already-plaintext regions.
        decrypted_path = tmp_dir / "decrypted.ncch"
        with ncch_path.open("rb") as f_in, decrypted_path.open("wb") as f_out:
            shutil.copyfileobj(f_in, f_out, length=1 << 20)

        # Decrypt the encrypted regions via ctrtool and place them at their
        # declared offsets. The extended-header region (header + exheader +
        # access descriptor) is encrypted; ctrtool's --exheader emits
        # exheader + access descriptor together.
        if exheader_size:
            exh_path = tmp_dir / "exheader.bin"
            _ctrtool_decrypt_region(ctrtool, ncch_path, "--exheader", exh_path)
            _place_region(decrypted_path, exh_path, _EXHEADER_REGION_OFFSET)

        if exefs is not None:
            exefs_path = tmp_dir / "exefs.bin"
            _ctrtool_decrypt_region(ctrtool, ncch_path, "--exefs", exefs_path)
            _place_region(decrypted_path, exefs_path, exefs[0])

        if romfs is not None:
            romfs_path = tmp_dir / "romfs.bin"
            _ctrtool_decrypt_region(ctrtool, ncch_path, "--romfs", romfs_path)
            _place_region(decrypted_path, romfs_path, romfs[0])

        # Flip the NoCrypto bit so the assembled image reads as decrypted for
        # the downstream three_ds_ncch normalizer (which refuses encrypted
        # content). The header's declared protected hashes stay authoritative.
        _set_nocrypto(decrypted_path)

        return ByteView(
            source=_TempFileSource(decrypted_path, tmp_dir),
            format="3ds-ncch-enc",
        )
    except BaseException:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise
    finally:
        if staged_temp is not None:
            Path(staged_temp).unlink(missing_ok=True)


def _place_region(image: Path, region_file: Path, offset: int) -> None:
    """Write a decrypted region into the assembled image at ``offset``."""
    with region_file.open("rb") as f_reg:
        with image.open("r+b") as f_img:
            f_img.seek(offset)
            shutil.copyfileobj(f_reg, f_img, length=1 << 20)


def _set_nocrypto(image: Path) -> None:
    with image.open("r+b") as f:
        f.seek(_OTHER_FLAGS_OFFSET)
        flag = f.read(1)[0]
        f.seek(_OTHER_FLAGS_OFFSET)
        f.write(bytes([flag | _NO_ENCRYPTION]))
