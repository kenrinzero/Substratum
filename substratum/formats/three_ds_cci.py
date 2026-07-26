"""Nintendo 3DS CCI/NCSD outer-container normalizer.

This unit reads only the fixed NCSD header and returns the present NCCH
partitions as opaque slices into the original image.  It does not parse NCCH
regions, ExeFS, or RomFS; callers compose those later normalization layers
explicitly (DESIGN.md section 1).

Runtime is stdlib-only.  All NCSD and NCCH offsets/sizes use 0x200-byte media
units.
"""

from __future__ import annotations

import struct

from substratum.contract import ByteSource, FileEntry, FileSource, FileTree

__all__ = ["sniff", "normalize_3ds_cci"]

_MEDIA_UNIT = 0x200
_NCSD_HEADER_SIZE = 0x200
_NCSD_MAGIC_OFFSET = 0x100
_PARTITION_TABLE_OFFSET = 0x120
_PARTITION_IDS_OFFSET = 0x190
_PARTITION_COUNT = 8
_NCCH_HEADER_OFFSET = 0x100
_NCCH_HEADER_FIELDS_SIZE = 0x10


def sniff(source: ByteSource) -> bool:
    """Return true when ``source`` carries the NCSD magic at 0x100."""
    return (
        source.size() >= _NCSD_MAGIC_OFFSET + 4
        and source.read_at(_NCSD_MAGIC_OFFSET, 4) == b"NCSD"
    )


def _partition_name(slot: int) -> str:
    return f"partition{slot}.{'cxi' if slot == 0 else 'cfa'}"


def normalize_3ds_cci(source) -> FileTree:
    """Expose one CCI/NCSD layer as opaque NCCH partition slices."""
    src = source if isinstance(source, ByteSource) else FileSource(source)
    source_size = src.size()
    if source_size < _NCSD_HEADER_SIZE:
        raise ValueError("source too small to contain a 3DS NCSD header")

    header = src.read_at(0, _NCSD_HEADER_SIZE)
    if header[_NCSD_MAGIC_OFFSET : _NCSD_MAGIC_OFFSET + 4] != b"NCSD":
        raise ValueError("not a 3DS CCI/NCSD image (missing NCSD magic)")

    declared_units = struct.unpack_from("<I", header, 0x104)[0]
    declared_size = declared_units * _MEDIA_UNIT
    if declared_size != source_size:
        raise ValueError(
            f"declared media size {declared_size} does not match "
            f"CCI size {source_size}"
        )

    partitions: list[tuple[int, int, int, int]] = []
    seen_ids: dict[int, int] = {}
    for slot in range(_PARTITION_COUNT):
        offset_units, size_units = struct.unpack_from(
            "<II", header, _PARTITION_TABLE_OFFSET + slot * 8
        )
        partition_id = struct.unpack_from(
            "<Q", header, _PARTITION_IDS_OFFSET + slot * 8
        )[0]

        if offset_units == 0 and size_units == 0:
            if partition_id != 0:
                raise ValueError(
                    f"empty partition slot {slot} has nonzero ID "
                    f"{partition_id:016x}"
                )
            continue
        if offset_units == 0 or size_units == 0:
            raise ValueError(
                f"half-empty partition entry in slot {slot}: "
                f"offset={offset_units}, size={size_units}"
            )

        offset = offset_units * _MEDIA_UNIT
        size = size_units * _MEDIA_UNIT
        end = offset + size
        if offset < _NCSD_HEADER_SIZE:
            raise ValueError(
                f"partition {slot} at {offset:#x} overlaps the NCSD header"
            )
        if end > source_size:
            raise ValueError(
                f"partition {slot} range [{offset:#x}, {end:#x}) "
                f"exceeds CCI size {source_size:#x}"
            )
        if size < _NCCH_HEADER_OFFSET + _NCCH_HEADER_FIELDS_SIZE:
            raise ValueError(
                f"partition {slot} is too small to contain an NCCH header"
            )
        if partition_id == 0:
            raise ValueError(f"populated partition slot {slot} has zero ID")
        if partition_id in seen_ids:
            raise ValueError(
                f"partition {slot} duplicates partition ID "
                f"{partition_id:016x} from slot {seen_ids[partition_id]}"
            )
        seen_ids[partition_id] = slot
        partitions.append((slot, offset, size, partition_id))

    if not partitions:
        raise ValueError("NCSD contains no partitions")

    by_offset = sorted(partitions, key=lambda item: item[1])
    for left, right in zip(by_offset, by_offset[1:]):
        left_slot, left_offset, left_size, _ = left
        right_slot, right_offset, _, _ = right
        if left_offset + left_size > right_offset:
            raise ValueError(
                f"partition {right_slot} overlaps partition {left_slot}"
            )

    entries: list[FileEntry] = []
    for slot, offset, size, partition_id in partitions:
        fields = src.read_at(
            offset + _NCCH_HEADER_OFFSET, _NCCH_HEADER_FIELDS_SIZE
        )
        if fields[:4] != b"NCCH":
            raise ValueError(f"partition {slot} lacks NCCH magic")
        ncch_size_units = struct.unpack_from("<I", fields, 4)[0]
        ncch_size = ncch_size_units * _MEDIA_UNIT
        if ncch_size != size:
            raise ValueError(
                f"partition {slot} NCCH size {ncch_size} does not match "
                f"NCSD table size {size}"
            )
        ncch_title_id = struct.unpack_from("<Q", fields, 8)[0]
        if ncch_title_id != partition_id:
            raise ValueError(
                f"partition {slot} NCSD ID does not match NCCH title ID"
            )
        entries.append(
            FileEntry(
                path=_partition_name(slot),
                kind="file",
                offset=offset,
                size=size,
            )
        )

    return FileTree(source=src, format="3ds-cci", entries=tuple(entries))
