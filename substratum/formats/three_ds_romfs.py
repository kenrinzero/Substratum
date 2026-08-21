"""3DS RomFS filesystem normalizer (NORMALIZERS.md row `3ds-romfs`).

Scope:
- Parses a decrypted RomFS region (the NCCH `romfs.bin` layer, IVFC
  wrapped) into a FileTree whose byte ranges point directly into the
  region — no spool, no materialization.
- Eagerly verifies the complete IVFC hash tree (master <- level0 <-
  level1 <- data, partial trailing block zero-padded) and the closed-form
  size identities linking every table size to its block count. This is
  the strongest structural gate in the unit: a single flipped payload
  byte dies here.
- Physical layout (characterized on staged retail media + ctrtool's
  interpretation, 2026-08-21): the declared level offsets describe the
  canonical pre-data chain [0, align(l0), align(l0)+align(l1)], but the
  3DS relocates — level-3 data sits at align(header+master table, block)
  and the level-0/level-1 tables follow AFTER the data, with the level-1
  padded end exactly the region end.
- Refuses rather than guesses (structural red): bad IVFC magic/version,
  wrong header size, unresolvable declared/actual geometry, hash-chain
  or size-identity mismatch, malformed level-3 header, non-tiling
  tables, traversal/cyclic directory or file chains, parent-link
  disagreement, duplicate paths, invalid path components, and file
  ranges outside the region.

Names are genuine UTF-16LE (JP corpus titles carry non-ASCII names —
unlike the ASCII-only units, valid Unicode is accepted; the canonical
manifest escapes it). Runtime is stdlib-only per DESIGN.md § 4.
"""

from __future__ import annotations

import hashlib
import struct

from substratum.contract import ByteSource, FileEntry, FileSource, FileTree

__all__ = ["sniff", "normalize_3ds_romfs"]

_MAGIC = 0x43465649  # 'IVFC'
_VERSION = 0x00010000
_HDR_SIZE_FIELD = 0x54
_EXPECTED_HDR_SIZE = 0x5C
_META_HDR = 0x28
_NONE = 0xFFFFFFFF
_BLOCK_MIN = 0x200
_BLOCK_MAX = 0x10000
_DIR_FIXED = 0x18   # parent, sibling, child, firstFile, hashNext, nameLen
_FILE_FIXED = 0x20  # parent, sibling, u64 offset, u64 size, hashNext, nameLen


def _align(n: int, a: int) -> int:
    return n + (-n % a)


def _parse_header(src: ByteSource, size: int):
    """Parse and cross-check the IVFC header; return the level geometry."""
    if size < _EXPECTED_HDR_SIZE:
        raise ValueError("region too small for an IVFC header")
    head = src.read_at(0, _EXPECTED_HDR_SIZE)
    magic, version, mhs = struct.unpack_from("<III", head, 0)
    if magic != _MAGIC:
        raise ValueError("not a 3DS RomFS region (bad IVFC magic)")
    if version != _VERSION:
        raise ValueError(f"unsupported IVFC version {version:#010x}")
    declared = []
    for lvl in range(3):
        off, lsize, log_block, _rsvd = struct.unpack_from("<QQII", head, 0x0C + lvl * 0x18)
        declared.append((off, lsize, log_block))
    hdr_size = struct.unpack_from("<I", head, _HDR_SIZE_FIELD)[0]
    if hdr_size != _EXPECTED_HDR_SIZE:
        raise ValueError(f"unexpected IVFC header size field {hdr_size:#x}")

    block = 1 << declared[0][2]
    if not (_BLOCK_MIN <= block <= _BLOCK_MAX) or block % 0x200:
        raise ValueError(f"implausible IVFC block size {block:#x}")
    if any(d[2] != declared[0][2] for d in declared):
        raise ValueError("IVFC level block sizes disagree")

    (_, s0, _), (_, s1, _), (_, s_data, _) = declared
    n0 = -(-s1 // block)
    n1 = -(-s_data // block)
    n_m = -(-s0 // block)
    if s0 != n0 * 0x20 or s1 != n1 * 0x20 or mhs != n_m * 0x20:
        raise ValueError("IVFC table sizes do not match their block counts")
    if mhs == 0 or s0 == 0 or s1 == 0 or s_data == 0:
        raise ValueError("IVFC declares an empty level")

    mht_off = _align(hdr_size, 16)
    data_off = _align(mht_off + mhs, block)
    l0_off = _align(data_off + s_data, block)
    l1_off = _align(l0_off + s0, block)
    if _align(l1_off + s1, block) != size:
        raise ValueError("level-1 hash table does not end at the region end")

    want_declared = (0, _align(s0, block), _align(s0, block) + _align(s1, block))
    if tuple(d[0] for d in declared) != want_declared:
        raise ValueError("declared IVFC offsets do not follow the canonical chain")

    return mht_off, mhs, data_off, s_data, l0_off, s0, l1_off, s1, block


def _verify_hash_tree(src: ByteSource, mht_off, mhs, data_off, s_data, l0_off, s0, l1_off, s1, block):
    """Eagerly verify master <- L0 <- L1 <- data. Streaming, bounded RSS."""
    l0 = src.read_at(l0_off, s0)
    mht = src.read_at(mht_off, mhs)
    for i in range(len(mht) // 0x20):
        blk = src.read_at(l0_off + i * block, min(block, s0 - i * block))
        blk = blk + b"\x00" * (block - len(blk))
        if mht[i * 0x20 : (i + 1) * 0x20] != hashlib.sha256(blk).digest():
            raise ValueError(f"master hash mismatch at level-0 block {i}")

    l1 = src.read_at(l1_off, s1)
    for i in range(len(l0) // 0x20):
        blk = src.read_at(l1_off + i * block, min(block, s1 - i * block))
        blk = blk + b"\x00" * (block - len(blk))
        if l0[i * 0x20 : (i + 1) * 0x20] != hashlib.sha256(blk).digest():
            raise ValueError(f"level-0 hash mismatch at level-1 block {i}")

    n_full, rem = divmod(s_data, block)
    for i in range(n_full):
        blk = src.read_at(data_off + i * block, block)
        if l1[i * 0x20 : (i + 1) * 0x20] != hashlib.sha256(blk).digest():
            raise ValueError(f"level-1 hash mismatch at data block {i}")
    if rem:
        blk = src.read_at(data_off + n_full * block, rem)
        blk = blk + b"\x00" * (block - rem)
        if l1[n_full * 0x20 : (n_full + 1) * 0x20] != hashlib.sha256(blk).digest():
            raise ValueError("level-1 hash mismatch at trailing data block")


def _check_name(raw: bytes) -> str:
    if len(raw) % 2:
        raise ValueError("odd-length UTF-16 name")
    try:
        name = raw.decode("utf-16-le")
    except UnicodeDecodeError as exc:
        raise ValueError(f"invalid UTF-16 in RomFS name {raw!r}") from exc
    if not name or name in {".", ".."} or "/" in name or "\\" in name or ":" in name:
        raise ValueError(f"invalid RomFS path component {name!r}")
    if any(ord(c) < 0x20 for c in name):
        raise ValueError(f"control character in RomFS name {name!r}")
    return name


class _Tables:
    """The level-3 metadata tables, sliced out of the data region."""

    def __init__(self, src: ByteSource, data_off: int, s_data: int) -> None:
        meta = src.read_at(data_off, _META_HDR)
        (hlen, dht_off, dht_len, dt_off, dt_len,
         fht_off, fht_len, ft_off, ft_len, fdata_off) = struct.unpack("<10I", meta)
        if hlen != _META_HDR:
            raise ValueError(f"unexpected RomFS header length {hlen:#x}")
        if dht_off != _META_HDR or dt_off != dht_off + dht_len \
                or fht_off != dt_off + dt_len or ft_off != fht_off + fht_len:
            raise ValueError("RomFS metadata tables do not tile")
        if fdata_off != _align(ft_off + ft_len, 16):
            raise ValueError("RomFS file data is not 16-byte aligned after the tables")
        if fdata_off > s_data or dt_len == 0 or ft_len < _FILE_FIXED:
            raise ValueError("RomFS metadata tables exceed the data level")
        self.fdata_off = fdata_off
        self.dt = src.read_at(data_off + dt_off, dt_len)
        self.ft = src.read_at(data_off + ft_off, ft_len)
        # Bucket values index the dir/file tables, not the bucket tables.
        for table, bound in ((src.read_at(data_off + dht_off, dht_len), dt_len),
                             (src.read_at(data_off + fht_off, fht_len), ft_len)):
            for i in range(0, len(table), 4):
                v = struct.unpack_from("<I", table, i)[0]
                if v != _NONE and v >= bound:
                    raise ValueError("RomFS hash bucket points out of its table")

    def dir_entry(self, off: int):
        if off % 4 or off + _DIR_FIXED > len(self.dt):
            raise ValueError(f"directory entry at {off:#x} is out of bounds")
        parent, sibling, child, first_file, _hash_next = struct.unpack_from(
            "<5I", self.dt, off
        )
        name_len = struct.unpack_from("<I", self.dt, off + 0x14)[0]
        if off + _DIR_FIXED + name_len > len(self.dt):
            raise ValueError("directory name exceeds the table")
        return parent, sibling, child, first_file, self.dt[off + _DIR_FIXED : off + _DIR_FIXED + name_len]

    def file_entry(self, off: int):
        if off % 4 or off + _FILE_FIXED > len(self.ft):
            raise ValueError(f"file entry at {off:#x} is out of bounds")
        parent, sibling = struct.unpack_from("<II", self.ft, off)
        data_off, size = struct.unpack_from("<QQ", self.ft, off + 8)
        _hash_next = struct.unpack_from("<I", self.ft, off + 0x18)[0]
        name_len = struct.unpack_from("<I", self.ft, off + 0x1C)[0]
        if off + _FILE_FIXED + name_len > len(self.ft):
            raise ValueError("file name exceeds the table")
        return parent, sibling, data_off, size, self.ft[off + _FILE_FIXED : off + _FILE_FIXED + name_len]


def _walk(tables: _Tables, data_off: int, s_data: int) -> list[FileEntry]:
    """Depth-first walk: each directory, then its files, then subdirs."""
    entries: list[FileEntry] = []
    seen_paths: set[str] = set()

    def emit(path: str, kind: str, offset: int, size: int) -> None:
        if path in seen_paths:
            raise ValueError(f"duplicate RomFS path {path!r}")
        seen_paths.add(path)
        entries.append(FileEntry(path=path, kind=kind, offset=offset, size=size))

    def walk_files(dir_off: int, first: int, prefix: str) -> None:
        seen: set[int] = set()
        off = first
        while off != _NONE:
            if off in seen:
                raise ValueError(f"cyclic file sibling chain at {off:#x}")
            seen.add(off)
            parent, sibling, f_off, size, raw_name = tables.file_entry(off)
            if parent != dir_off:
                raise ValueError(
                    f"file at {off:#x} claims parent {parent:#x}, walker is in {dir_off:#x}"
                )
            name = _check_name(raw_name)
            path = f"{prefix}/{name}" if prefix else name
            if f_off + size > s_data - tables.fdata_off:
                raise ValueError(f"file {path!r} data range exceeds the data level")
            emit(path, "file", data_off + tables.fdata_off + f_off, size)
            off = sibling

    def walk_dirs(dir_off: int, prefix: str) -> None:
        parent, sibling, child, first_file, raw_name = tables.dir_entry(dir_off)
        if dir_off == 0:
            if parent != 0 or raw_name:
                raise ValueError("RomFS root entry is malformed")
        elif prefix == "":
            raise ValueError("non-root directory has an empty path")
        walk_files(dir_off, first_file, prefix)
        seen: set[int] = set()
        off = child
        while off != _NONE:
            if off in seen:
                raise ValueError(f"cyclic directory sibling chain at {off:#x}")
            seen.add(off)
            c_parent, _c_sib, _c_child, _c_file, c_raw = tables.dir_entry(off)
            if c_parent != dir_off:
                raise ValueError(
                    f"directory at {off:#x} claims parent {c_parent:#x}, walker is in {dir_off:#x}"
                )
            name = _check_name(c_raw)
            path = f"{prefix}/{name}" if prefix else name
            emit(path, "dir", 0, 0)
            walk_dirs(off, path)
            off = tables.dir_entry(off)[1]

    walk_dirs(0, "")
    if not entries:
        raise ValueError("RomFS tree is empty")
    return entries


def sniff(source: ByteSource) -> bool:
    """True when the source carries a v1 IVFC header with a canonical
    declared level chain."""
    if source.size() < _EXPECTED_HDR_SIZE:
        return False
    try:
        _parse_header(source, source.size())
    except (ValueError, OSError):
        return False
    return True


def normalize_3ds_romfs(source) -> FileTree:
    """Parse a decrypted 3DS RomFS region into a FileTree."""
    src = source if isinstance(source, ByteSource) else FileSource(source)
    size = src.size()
    (mht_off, mhs, data_off, s_data, l0_off, s0, l1_off, s1, block) = _parse_header(src, size)
    _verify_hash_tree(src, mht_off, mhs, data_off, s_data, l0_off, s0, l1_off, s1, block)
    tables = _Tables(src, data_off, s_data)
    entries = _walk(tables, data_off, s_data)
    return FileTree(source=src, format="3ds-romfs", entries=tuple(entries))
