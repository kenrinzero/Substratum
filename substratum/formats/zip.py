"""ZIP archive filesystem normalizer (NORMALIZERS.md row `zip`).

Scope:
- Parses a ZIP container (stored + deflate members, data descriptors,
  ZIP64 sizes/offsets/records) into a FileTree over a decompression
  spool: deflate is not seekable, so every file payload is extracted to
  one temp spool file (the `chd` pattern), and each entry's byte range
  points into that spool.
- Spool layout (documented, load-bearing for manifests): file payloads
  are written in ascending path order — the same ordering
  `canonical_manifest` uses — back to back; directories contribute
  nothing. Central-directory order is walk order for `entries`, never
  the spool layout.
- Refuses rather than guesses (structural red): bad EOCD/CD/local
  magics, multi-disk archives, encrypted members, unsupported
  compression methods, zip64 sentinels without a resolvable ZIP64
  record, local/central disagreement, out-of-bounds or post-CD data,
  CRC or inflated-size mismatch, duplicate names, and empty/dot/
  traversal/backslash/absolute path components.

The spool is owned by the returned tree's source: explicit idempotent
`close()`, context management, and a `weakref.finalize` fallback that
unlinks the spool file.

Runtime is stdlib-only per DESIGN.md § 4.
"""

from __future__ import annotations

import os
import struct
import tempfile
import weakref
import zlib
from pathlib import Path

from substratum.contract import ByteSource, FileEntry, FileSource, FileTree

__all__ = ["sniff", "normalize_zip"]

_LOCAL_SIG = 0x04034B50
_CD_SIG = 0x02014B50
_EOCD_SIG = 0x06054B50
_Z64_EOCD_SIG = 0x06064B50
_Z64_LOC_SIG = 0x07064B50
_DESC_SIG = 0x08074B50

_EOCD_LEN = 22
_Z64_LOC_LEN = 20
_Z64_EOCD_LEN = 56
_Z64_EXTRA_ID = 0x0001
_SENTINEL32 = 0xFFFFFFFF
_SENTINEL16 = 0xFFFF

_EOCD_SCAN_CAP = _EOCD_LEN + 0xFFFF  # EOCD + maximum archive comment
_METHOD_STORED = 0
_METHOD_DEFLATE = 8
_FLAG_ENCRYPTED = 0x0001
_FLAG_DESCRIPTOR = 0x0008
_FLAG_UTF8 = 0x0800
_FLAG_RESERVED = 0xE000
_SPOOL_CHUNK = 1 << 20  # 1 MiB — matches the gate's fidelity chunk

_local_hdr = struct.Struct("<IHHHHHIIIHH")
_cd_hdr = struct.Struct("<IHHHHHHIIIHHHHHII")
_eocd_hdr = struct.Struct("<HHHHIIH")
_z64_eocd_hdr = struct.Struct("<IQHHIIQQQQ")
_z64_loc_hdr = struct.Struct("<IIQI")


def _safe_unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


class _SpoolSource:
    """ByteSource over the decompression spool that owns the temp file."""

    def __init__(self, path: str) -> None:
        self._inner = FileSource(path)
        self._finalizer = weakref.finalize(self, _safe_unlink, path)

    def read_at(self, offset: int, size: int) -> bytes:
        return self._inner.read_at(offset, size)

    def size(self) -> int:
        return self._inner.size()

    def close(self) -> None:
        """Unlink the spool; safe to call more than once."""
        self._finalizer()

    def __enter__(self) -> _SpoolSource:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()


def _find_eocd(src: ByteSource, size: int) -> int:
    """Locate the EOCD record whose comment ends exactly at EOF."""
    window = min(size, _EOCD_SCAN_CAP)
    tail = src.read_at(size - window, window)
    pos = tail.rfind(b"PK\x05\x06")
    while pos >= 0:
        if pos + _EOCD_LEN <= len(tail):
            comment_len = struct.unpack_from("<H", tail, pos + 20)[0]
            if pos + _EOCD_LEN + comment_len == len(tail):
                return size - window + pos
        pos = tail.rfind(b"PK\x05\x06", 0, pos)
    raise ValueError("no end of central directory record at end of file")


def _central_bounds(src: ByteSource, size: int, eocd_off: int) -> tuple[int, int, int]:
    """Return (cd_offset, cd_size, entry_count), resolving the ZIP64 chain.

    Sentinel fields in the plain EOCD must resolve through the ZIP64
    locator + record; when both records carry real values they must agree.
    """
    eocd = _eocd_hdr.unpack(
        src.read_at(eocd_off + 4, _EOCD_LEN - 4)
    )
    disk, cd_disk, n_disk, n_total, cd_size, cd_off = eocd[:6]
    if disk != 0 or cd_disk != 0:
        raise ValueError("multi-disk archives are out of scope")

    locator = src.read_at(max(0, eocd_off - _Z64_LOC_LEN), _Z64_LOC_LEN)
    has_locator = (
        eocd_off >= _Z64_LOC_LEN
        and struct.unpack_from("<I", locator, 0)[0] == _Z64_LOC_SIG
    )
    needs_zip64 = (
        cd_size == _SENTINEL32
        or cd_off == _SENTINEL32
        or n_total == _SENTINEL16
        or n_disk == _SENTINEL16
    )
    if needs_zip64 and not has_locator:
        raise ValueError("ZIP64 sentinel fields without a ZIP64 locator")

    if has_locator:
        _, z64_disk, z64_off, n_disks = _z64_loc_hdr.unpack(locator)
        if z64_disk != 0 or n_disks != 1:
            raise ValueError("multi-disk archives are out of scope")
        if z64_off + _Z64_EOCD_LEN > eocd_off - _Z64_LOC_LEN:
            raise ValueError("ZIP64 end record out of bounds")
        record = src.read_at(z64_off, _Z64_EOCD_LEN)
        if struct.unpack_from("<I", record, 0)[0] != _Z64_EOCD_SIG:
            raise ValueError("ZIP64 locator points at a non-ZIP64 record")
        rest_size = struct.unpack_from("<Q", record, 4)[0]
        if rest_size < _Z64_EOCD_LEN - 12:
            raise ValueError("ZIP64 end record is truncated")
        (
            _vmade,
            _vneed,
            z64_disk_no,
            z64_cd_disk,
            z64_n_disk,
            z64_n_total,
            z64_cd_size,
            z64_cd_off,
        ) = struct.unpack_from("<HHIIQQQQ", record, 12)
        if z64_disk_no != 0 or z64_cd_disk != 0:
            raise ValueError("multi-disk archives are out of scope")
        if z64_n_disk != z64_n_total:
            raise ValueError("ZIP64 record entry counts disagree")
        # cross-check every non-sentinel plain-EOCD field
        if n_total != _SENTINEL16 and n_total != z64_n_total:
            raise ValueError("EOCD and ZIP64 entry counts disagree")
        if cd_size != _SENTINEL32 and cd_size != z64_cd_size:
            raise ValueError("EOCD and ZIP64 central-directory sizes disagree")
        if cd_off != _SENTINEL32 and cd_off != z64_cd_off:
            raise ValueError("EOCD and ZIP64 central-directory offsets disagree")
        n_total, cd_size, cd_off = z64_n_total, z64_cd_size, z64_cd_off

    if cd_off + cd_size > size:
        raise ValueError("central directory exceeds archive size")
    return cd_off, cd_size, n_total


def _apply_zip64_extra(extra: bytes, usize: int, csize: int, offset: int) -> tuple[int, int, int]:
    """Substitute ZIP64 extra values for 0xFFFFFFFF sentinels, in the
    spec order (usize, csize, offset, disk — sizes only as sentineled)."""
    i = 0
    while i + 4 <= len(extra):
        header_id, data_len = struct.unpack_from("<HH", extra, i)
        body = extra[i + 4 : i + 4 + data_len]
        if len(body) != data_len:
            raise ValueError("malformed extra field in central directory")
        if header_id == _Z64_EXTRA_ID:
            j = 0
            if usize == _SENTINEL32:
                if j + 8 > len(body):
                    raise ValueError("truncated ZIP64 extra field")
                usize = struct.unpack_from("<Q", body, j)[0]
                j += 8
            if csize == _SENTINEL32:
                if j + 8 > len(body):
                    raise ValueError("truncated ZIP64 extra field")
                csize = struct.unpack_from("<Q", body, j)[0]
                j += 8
            if offset == _SENTINEL32:
                if j + 8 > len(body):
                    raise ValueError("truncated ZIP64 extra field")
                offset = struct.unpack_from("<Q", body, j)[0]
                j += 8
        i += 4 + data_len
    return usize, csize, offset


def _apply_zip64_extra_local(extra: bytes) -> tuple[int, int]:
    """Resolve 0xFFFFFFFF local size sentinels through the local ZIP64
    extra field (usize then csize, per the spec order)."""
    i = 0
    while i + 4 <= len(extra):
        header_id, data_len = struct.unpack_from("<HH", extra, i)
        body = extra[i + 4 : i + 4 + data_len]
        if len(body) != data_len:
            raise ValueError("malformed extra field in local header")
        if header_id == _Z64_EXTRA_ID:
            if len(body) < 16:
                raise ValueError("truncated ZIP64 extra field in local header")
            return struct.unpack_from("<QQ", body, 0)
        i += 4 + data_len
    raise ValueError("ZIP64 local size sentinels without a ZIP64 extra field")


def _decode_name(raw: bytes, utf8_flag: bool) -> str:
    if utf8_flag:
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"invalid UTF-8 in ZIP name {raw!r}") from exc
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"non-ASCII bytes in ZIP name {raw!r} without the UTF-8 flag "
            "(ambiguous legacy encoding — refused)"
        ) from exc


def _check_path(name: str) -> str:
    """Validate a member path and return it without the dir slash."""
    if not name or name.startswith("/"):
        raise ValueError(f"invalid ZIP path {name!r}")
    is_dir = name.endswith("/")
    path = name[:-1] if is_dir else name
    if not path or "\\" in path:
        raise ValueError(f"invalid ZIP path {name!r}")
    for component in path.split("/"):
        if not component or component in {".", ".."} or ":" in component:
            raise ValueError(f"invalid ZIP path component in {name!r}")
    return path


def _parse_central(src: ByteSource, size: int) -> list[dict]:
    """Parse the central directory into member dicts, validating every
    local header against its central record."""
    eocd_off = _find_eocd(src, size)
    cd_off, cd_size, declared_count = _central_bounds(src, size, eocd_off)

    members: list[dict] = []
    seen: set[str] = set()
    pos = cd_off
    end = cd_off + cd_size
    while pos < end:
        if pos + _cd_hdr.size > end:
            raise ValueError("central directory entry is truncated")
        fields = _cd_hdr.unpack_from(src.read_at(pos, 46), 0)
        if fields[0] != _CD_SIG:
            raise ValueError("bad central directory entry magic")
        (_, _vmade, _vneed, flags, method, _time, _date, crc,
         csize, usize, nlen, elen, clen, disk_start, _iattr, _eattr,
         offset) = fields
        if pos + 46 + nlen + elen + clen > end:
            raise ValueError("central directory entry exceeds the directory")
        name_raw = src.read_at(pos + 46, nlen)
        extra = src.read_at(pos + 46 + nlen, elen)
        pos += 46 + nlen + elen + clen

        if disk_start != 0:
            raise ValueError("multi-disk archives are out of scope")
        if flags & _FLAG_ENCRYPTED:
            raise ValueError("encrypted members are out of scope")
        if flags & _FLAG_RESERVED:
            raise ValueError(f"reserved ZIP flag bits set ({flags:#06x})")
        if method not in (_METHOD_STORED, _METHOD_DEFLATE):
            raise ValueError(f"unsupported compression method {method}")
        usize, csize, offset = _apply_zip64_extra(extra, usize, csize, offset)

        name = _decode_name(name_raw, bool(flags & _FLAG_UTF8))
        path = _check_path(name)
        is_dir = name.endswith("/")
        if is_dir and (usize != 0 or csize != 0):
            raise ValueError(f"directory entry {name!r} carries data")
        if path in seen:
            raise ValueError(f"duplicate member path {path!r}")
        seen.add(path)

        # --- validate the local header against this central record ---
        if offset + _local_hdr.size > cd_off:
            raise ValueError(f"member {path!r} local header out of bounds")
        local = _local_hdr.unpack_from(src.read_at(offset, 30), 0)
        (_, _lvneed, l_flags, l_method, _lt, _ld, l_crc,
         l_csize, l_usize, l_nlen, l_elen) = local
        if local[0] != _LOCAL_SIG:
            raise ValueError(f"member {path!r} has a bad local header magic")
        if l_nlen != nlen or src.read_at(offset + 30, l_nlen) != name_raw:
            raise ValueError(f"member {path!r} local name disagrees with central")
        if l_method != method:
            raise ValueError(f"member {path!r} local method disagrees with central")
        if (l_flags & _FLAG_UTF8) != (flags & _FLAG_UTF8):
            raise ValueError(f"member {path!r} local flags disagree with central")
        if not flags & _FLAG_DESCRIPTOR:
            if l_csize == _SENTINEL32 or l_usize == _SENTINEL32:
                l_usize, l_csize = _apply_zip64_extra_local(
                    src.read_at(offset + 30 + l_nlen, l_elen)
                )
            if l_crc != crc or l_csize != csize or l_usize != usize:
                raise ValueError(
                    f"member {path!r} local header disagrees with central directory"
                )
        data_off = offset + 30 + l_nlen + l_elen
        if data_off + csize > cd_off:
            raise ValueError(f"member {path!r} data range is out of bounds")

        members.append(
            {
                "path": path,
                "kind": "dir" if is_dir else "file",
                "crc": crc,
                "csize": csize,
                "usize": usize,
                "method": method,
                "data_off": data_off,
            }
        )

    if pos != end:
        raise ValueError("central directory size does not match its entries")
    if len(members) != declared_count:
        raise ValueError(
            f"central directory holds {len(members)} entries, EOCD declares {declared_count}"
        )
    if not members:
        raise ValueError("empty archive")
    return members


def _spool_member(fh, src: ByteSource, member: dict) -> int:
    """Extract one member into the spool; return bytes written. Streaming,
    bounded-memory, CRC-32 checked against the central directory."""
    crc_running = 0
    produced = 0
    pos = member["data_off"]
    remaining = member["csize"]
    dec = zlib.decompressobj(-15) if member["method"] == _METHOD_DEFLATE else None
    while remaining > 0:
        chunk = src.read_at(pos, min(_SPOOL_CHUNK, remaining))
        if not chunk:
            raise ValueError(f"member {member['path']!r} data is truncated")
        out = dec.decompress(chunk) if dec is not None else chunk
        if out:
            fh.write(out)
            crc_running = zlib.crc32(out, crc_running)
            produced += len(out)
        pos += len(chunk)
        remaining -= len(chunk)
    if dec is not None:
        tail = dec.flush()
        if tail:
            fh.write(tail)
            crc_running = zlib.crc32(tail, crc_running)
            produced += len(tail)
        if not dec.eof:
            raise ValueError(f"member {member['path']!r} deflate stream is truncated")
        if dec.unused_data:
            raise ValueError(f"member {member['path']!r} has trailing compressed bytes")
    if produced != member["usize"]:
        raise ValueError(
            f"member {member['path']!r} inflated to {produced} bytes, "
            f"declared {member['usize']}"
        )
    if crc_running & 0xFFFFFFFF != member["crc"]:
        raise ValueError(f"member {member['path']!r} checksum mismatch")
    return produced


def sniff(source: ByteSource) -> bool:
    """True when the source ends with a ZIP EOCD resolving to a central
    directory that starts inside the file."""
    if source.size() < _EOCD_LEN:
        return False
    try:
        cd_off, cd_size, count = _central_bounds(
            source, source.size(), _find_eocd(source, source.size())
        )
        if count > 0:
            if struct.unpack("<I", source.read_at(cd_off, 4))[0] != _CD_SIG:
                return False
    except (ValueError, OSError):
        return False
    return True


def normalize_zip(source) -> FileTree:
    """Parse a ZIP archive into a FileTree over the decompression spool."""
    src = source if isinstance(source, ByteSource) else FileSource(source)
    size = src.size()
    members = _parse_central(src, size)

    # Documented spool layout: file payloads in ascending path order.
    files = sorted((m for m in members if m["kind"] == "file"), key=lambda m: m["path"])

    fd, spool_path = tempfile.mkstemp(prefix="substratum-zip-", suffix=".spool")
    try:
        with os.fdopen(fd, "wb") as fh:
            cursor = 0
            for member in files:
                member["offset"] = cursor
                cursor += _spool_member(fh, src, member)
    except BaseException:
        _safe_unlink(spool_path)
        raise

    entries = tuple(
        FileEntry(
            path=m["path"],
            kind=m["kind"],
            offset=m.get("offset", 0),
            size=m["usize"] if m["kind"] == "file" else 0,
        )
        for m in members
    )
    return FileTree(source=_SpoolSource(spool_path), format="zip", entries=entries)
