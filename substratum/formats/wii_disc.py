"""Unkeyed Wii disc partition-table normalizer.

The returned FileTree contains only opaque encrypted partition slices. It
does not derive title keys, decrypt clusters, or traverse the inner Wii FST.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from substratum.contract import ByteSource, FileEntry, FileSource, FileTree

__all__ = ["sniff", "normalize_wii_disc"]

_WII_MAGIC = 0x5D1C9EA3
_MAGIC_OFFSET = 0x18
_PARTITION_DIRECTORY_OFFSET = 0x40000
_PARTITION_DIRECTORY_SIZE = 0x20
_PARTITION_TABLE_MIN_OFFSET = (
    _PARTITION_DIRECTORY_OFFSET + _PARTITION_DIRECTORY_SIZE
)
_PARTITION_HEADER_SIZE = 0x2C0
_H3_SIZE = 0x18000
_WORD_SIZE = 4
_PARTITION_TYPES = {
    0: ("DATA", "partition-data.bin"),
    1: ("UPDATE", "partition-update.bin"),
    2: ("CHANNEL", "partition-channel.bin"),
}


@dataclass(frozen=True, slots=True)
class _Range:
    label: str
    offset: int
    size: int


@dataclass(frozen=True, slots=True)
class _Partition:
    label: str
    path: str
    offset: int
    size: int


def sniff(source: ByteSource) -> bool:
    """Return true when ``source`` carries the Wii disc magic."""
    return (
        source.size() >= _MAGIC_OFFSET + 4
        and struct.unpack(">I", source.read_at(_MAGIC_OFFSET, 4))[0]
        == _WII_MAGIC
    )


def _checked_metadata_range(
    *,
    label: str,
    name: str,
    offset: int,
    size: int,
    data_offset: int,
) -> _Range:
    if offset == 0 or size == 0:
        raise ValueError(f"half-empty {label} {name} range")
    end = offset + size
    if offset < _PARTITION_HEADER_SIZE or end > data_offset:
        raise ValueError(
            f"{label} {name} range [{offset:#x}, {end:#x}) "
            f"falls outside partition metadata area"
        )
    return _Range(name, offset, size)


def _parse_partition(
    src: ByteSource,
    *,
    source_size: int,
    offset: int,
    type_id: int,
) -> _Partition:
    label, path = _PARTITION_TYPES[type_id]
    if offset == 0:
        raise ValueError(f"{label} partition has zero offset")
    if offset < _PARTITION_TABLE_MIN_OFFSET:
        raise ValueError(f"{label} partition overlaps Wii disc metadata")
    if offset + _PARTITION_HEADER_SIZE > source_size:
        raise ValueError(f"{label} partition header exceeds disc")

    header = src.read_at(offset, _PARTITION_HEADER_SIZE)
    tmd_size = struct.unpack_from(">I", header, 0x2A4)[0]
    tmd_offset = struct.unpack_from(">I", header, 0x2A8)[0] * _WORD_SIZE
    cert_size = struct.unpack_from(">I", header, 0x2AC)[0]
    cert_offset = struct.unpack_from(">I", header, 0x2B0)[0] * _WORD_SIZE
    h3_offset = struct.unpack_from(">I", header, 0x2B4)[0] * _WORD_SIZE
    data_offset_words, data_size_words = struct.unpack_from(
        ">II", header, 0x2B8
    )
    if data_offset_words == 0 or data_size_words == 0:
        raise ValueError(f"half-empty {label} data range")
    data_offset = data_offset_words * _WORD_SIZE
    data_size = data_size_words * _WORD_SIZE
    if data_offset < _PARTITION_HEADER_SIZE:
        raise ValueError(f"{label} data region overlaps partition header")

    metadata = [
        _checked_metadata_range(
            label=label,
            name="TMD",
            offset=tmd_offset,
            size=tmd_size,
            data_offset=data_offset,
        ),
        _checked_metadata_range(
            label=label,
            name="certificate",
            offset=cert_offset,
            size=cert_size,
            data_offset=data_offset,
        ),
        _checked_metadata_range(
            label=label,
            name="H3",
            offset=h3_offset,
            size=_H3_SIZE,
            data_offset=data_offset,
        ),
    ]
    by_offset = sorted(metadata, key=lambda region: region.offset)
    for left, right in zip(by_offset, by_offset[1:]):
        if left.offset + left.size > right.offset:
            raise ValueError(
                f"{label} metadata ranges overlap: "
                f"{left.label} and {right.label}"
            )

    size = data_offset + data_size
    end = offset + size
    if end > source_size:
        raise ValueError(
            f"{label} partition range [{offset:#x}, {end:#x}) "
            f"exceeds disc size {source_size:#x}"
        )
    return _Partition(label, path, offset, size)


def normalize_wii_disc(source) -> FileTree:
    """Expose one Wii disc's encrypted partitions as lazy opaque slices."""
    src = source if isinstance(source, ByteSource) else FileSource(source)
    source_size = src.size()
    if source_size < _PARTITION_TABLE_MIN_OFFSET:
        raise ValueError("source too small to contain a Wii partition directory")
    if struct.unpack(">I", src.read_at(_MAGIC_OFFSET, 4))[0] != _WII_MAGIC:
        raise ValueError("not a Wii disc image (missing Wii disc magic)")

    directory = src.read_at(
        _PARTITION_DIRECTORY_OFFSET, _PARTITION_DIRECTORY_SIZE
    )
    tables: list[_Range] = []
    for group in range(4):
        count, offset_words = struct.unpack_from(">II", directory, group * 8)
        if count == 0 and offset_words == 0:
            continue
        if count == 0 or offset_words == 0:
            raise ValueError(f"half-empty partition group {group}")
        offset = offset_words * _WORD_SIZE
        size = count * 8
        if offset < _PARTITION_TABLE_MIN_OFFSET:
            raise ValueError(
                f"partition table {group} overlaps Wii disc metadata"
            )
        if offset + size > source_size:
            raise ValueError(f"partition table {group} exceeds disc")
        tables.append(_Range(str(group), offset, size))

    by_offset = sorted(tables, key=lambda table: table.offset)
    for left, right in zip(by_offset, by_offset[1:]):
        if left.offset + left.size > right.offset:
            raise ValueError(
                f"partition tables overlap: groups {left.label} and "
                f"{right.label}"
            )
    partition_count = sum(table.size // 8 for table in tables)
    if partition_count > len(_PARTITION_TYPES):
        raise ValueError(
            f"partition directory declares {partition_count} entries; "
            f"maximum supported is {len(_PARTITION_TYPES)}"
        )

    partitions: list[_Partition] = []
    seen_types: set[int] = set()
    for table in tables:
        raw_table = src.read_at(table.offset, table.size)
        for entry_offset in range(0, table.size, 8):
            offset_words, type_id = struct.unpack_from(
                ">II", raw_table, entry_offset
            )
            if type_id not in _PARTITION_TYPES:
                raise ValueError(f"unknown Wii partition type {type_id}")
            label, _ = _PARTITION_TYPES[type_id]
            if type_id in seen_types:
                raise ValueError(f"duplicate {label} partition")
            seen_types.add(type_id)
            partitions.append(
                _parse_partition(
                    src,
                    source_size=source_size,
                    offset=offset_words * _WORD_SIZE,
                    type_id=type_id,
                )
            )

    if not partitions:
        raise ValueError("no Wii partitions")

    by_offset = sorted(partitions, key=lambda partition: partition.offset)
    for left, right in zip(by_offset, by_offset[1:]):
        if left.offset + left.size > right.offset:
            raise ValueError(
                f"{right.label} partition overlaps {left.label} partition"
            )
    for table in tables:
        for partition in partitions:
            if (
                table.offset < partition.offset + partition.size
                and partition.offset < table.offset + table.size
            ):
                raise ValueError(
                    f"{partition.label} partition overlaps partition table "
                    f"{table.label}"
                )

    entries = tuple(
        FileEntry(partition.path, "file", partition.offset, partition.size)
        for partition in partitions
    )
    return FileTree(src, "wii-disc", entries)
