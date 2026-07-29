"""Wii encrypted-partition AES-CBC decode normalizer.

Input: one encrypted partition slice produced by ``wii-disc`` — a
``ByteSource`` / path whose byte range ``[0, partition_size)`` is a raw Wii
partition (ticket + TMD + certificates + H3 table + encrypted cluster data).

Output: one lazy ``ByteView`` over the *decrypted* 0x7C00-byte cluster
payloads, concatenated in cluster order. Per DESIGN.md §1 this is a decode
layer only — it returns a ``ByteView`` and never recurses into the inner Wii
filesystem (``wii-fst`` walks that in a separate, caller-composed step).

Key handling (docs/WII-KEYED-WORK.md): the standard Wii common AES key is
supplied by the operator as a raw 16-byte file named by the
``SUBSTRATUM_WII_COMMON_KEY_FILE`` environment variable. The loader fails
closed when the variable is unset, the file is missing, or its length is not
exactly 16. The key is never logged, hashed into a manifest, or written to
disk; code reports only whether the file exists and is exactly 16 bytes.

Crypto (wiibrew wiki, Wii disc / Ticket pages; yagcd):
  - The ticket sits at partition offset 0x000.
  - The 16-byte encrypted title key is at ticket offset 0x1BF.
  - Its AES-128-CBC IV is the 8-byte title ID at ticket offset 0x1DC, padded
    to 16 bytes with 8 zero bytes. The common key (index 0) decrypts it.
  - Each 0x8000-byte cluster is 0x400 bytes of hash header + 0x7C00 bytes of
    encrypted user data. The user data is AES-128-CBC decrypted with the
    title key, using bytes [0x3D0, 0x3E0) of the cluster's own hash header
    as the IV.
The cluster hash tree (H0/H1/H2/H3) is *not* verified here — partition
integrity is wit's independent responsibility at staging; this layer exposes
the decrypted payload bytes that wit agrees on.
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

from substratum._aes import aes128_cbc_decrypt
from substratum.contract import ByteSource, ByteView, FileSource, SliceSource

__all__ = ["sniff", "normalize_wii_partition"]

# ---- partition layout (mirrors wii_disc; duplicated intentionally so this   --
# -- unit is independently dispatchable on a raw partition slice, not coupled --
# -- to wii_disc's private header parser). -------------------------------------
_PARTITION_HEADER_SIZE = 0x2C0
_H3_SIZE = 0x18000
_WORD = 4

# Ticket field offsets (wiibrew: Ticket).
_TICKET_SIZE = 0x2A4
_TICKET_SIG_TYPE_OFFSET = 0x000
_TICKET_SIG_TYPE_RSA2048_SHA256 = 0x00010001  # disc tickets
_TICKET_TITLE_KEY_OFFSET = 0x1BF
_TICKET_TITLE_KEY_SIZE = 0x10
_TICKET_TITLE_ID_OFFSET = 0x1DC
_TICKET_TITLE_ID_SIZE = 0x08
_TICKET_COMMON_KEY_INDEX_OFFSET = 0x1F1
_STANDARD_COMMON_KEY_INDEX = 0

# Cluster layout (wiibrew: Wii disc).
_CLUSTER_SIZE = 0x8000
_CLUSTER_HASH_SIZE = 0x400
_CLUSTER_PAYLOAD_SIZE = 0x7C00
_CLUSTER_IV_OFFSET = 0x3D0
_CLUSTER_IV_SIZE = 0x10

# How big the decrypted view is (N payloads of 0x7C00 concatenated).
_AES_BLOCK = 16


def sniff(source: ByteSource) -> bool:
    """Heuristic: looks like a Wii partition's leading ticket region.

    A real sniff is inherently weak here — a partition slice has no magic of
    its own; the Wii disc magic lives in the outer disc header that
    ``wii-disc`` already validated. We accept sources large enough to hold a
    ticket + data region with a plausible ticket signature type. The
    dispatcher only reaches this sniffer via an explicit ``format=``
    pin in practice; composition from ``wii-disc`` is the documented path.
    """
    if source.size() < _TICKET_SIZE + _CLUSTER_SIZE:
        return False
    sig_type = struct.unpack(">I", source.read_at(0, 4))[0]
    return sig_type == 0x00010001  # RSA-2048 SHA-256 (disc tickets)


def _load_common_key() -> bytes:
    """Load the operator-supplied standard Wii common key.

    Named by ``SUBSTRATUM_WII_COMMON_KEY_FILE``; must be exactly 16 raw bytes.
    Fails closed with a message that never echoes key contents. The path is
    not logged either — only the fact of presence/correct size is reportable.
    """
    raw = os.environ.get("SUBSTRATUM_WII_COMMON_KEY_FILE")
    if not raw:
        raise ValueError(
            "SUBSTRATUM_WII_COMMON_KEY_FILE is not set; supply the raw "
            "16-byte standard Wii common key (see docs/WII-KEYED-WORK.md)"
        )
    path = Path(raw)
    if not path.is_file():
        raise ValueError(
            "SUBSTRATUM_WII_COMMON_KEY_FILE points to a missing file "
            "(see docs/WII-KEYED-WORK.md)"
        )
    key = path.read_bytes()
    if len(key) != 16:
        raise ValueError(
            "SUBSTRATUM_WII_COMMON_KEY_FILE must be exactly 16 bytes "
            "(see docs/WII-KEYED-WORK.md)"
        )
    return key


def _parse_partition_data_region(src: ByteSource) -> tuple[int, int]:
    """Return ``(data_offset, data_size)`` for the encrypted cluster area.

    Reads the partition header at offset 0 and extracts the data region
    fields at 0x2B8/0x2BC (word-offset/word-size, ×4 → bytes). Validates the
    region is block-aligned and sits after the metadata area.
    """
    size = src.size()
    if size < _PARTITION_HEADER_SIZE:
        raise ValueError("source too small to hold a Wii partition header")
    header = src.read_at(0, _PARTITION_HEADER_SIZE)
    data_off_words, data_size_words = struct.unpack_from(">II", header, 0x2B8)
    if data_off_words == 0 or data_size_words == 0:
        raise ValueError("half-empty partition data range")
    data_off = data_off_words * _WORD
    data_size = data_size_words * _WORD
    if data_off < _PARTITION_HEADER_SIZE:
        raise ValueError("partition data region overlaps the header")
    if data_size % _CLUSTER_SIZE != 0:
        raise ValueError(
            f"partition data size {data_size:#x} is not cluster-aligned"
        )
    if data_off + data_size > size:
        raise ValueError(
            f"partition data range [{data_off:#x}, {data_off + data_size:#x}) "
            f"exceeds source size {size:#x}"
        )
    return data_off, data_size


def _derive_title_key(src: ByteSource, common_key: bytes) -> bytes:
    """Decrypt the partition title key from the ticket at offset 0.

    Returns the 16-byte title key. Reads only the ticket region; the common
    key and title key are kept in memory and never persisted/logged.
    """
    if src.size() < _TICKET_SIZE:
        raise ValueError("source too small to hold a Wii ticket")
    ticket = src.read_at(0, _TICKET_SIZE)
    sig_type = struct.unpack_from(">I", ticket, _TICKET_SIG_TYPE_OFFSET)[0]
    if sig_type != _TICKET_SIG_TYPE_RSA2048_SHA256:
        raise ValueError(
            f"unsupported ticket signature type {sig_type:#x}; expected "
            f"RSA-2048 SHA-256 ({_TICKET_SIG_TYPE_RSA2048_SHA256:#x})"
        )
    key_index = ticket[_TICKET_COMMON_KEY_INDEX_OFFSET]
    if key_index != _STANDARD_COMMON_KEY_INDEX:
        raise ValueError(
            f"unsupported common-key index {key_index}; only standard Wii "
            f"common key (index {_STANDARD_COMMON_KEY_INDEX}) is supported"
        )
    enc_title_key = ticket[
        _TICKET_TITLE_KEY_OFFSET : _TICKET_TITLE_KEY_OFFSET + _TICKET_TITLE_KEY_SIZE
    ]
    title_id = ticket[
        _TICKET_TITLE_ID_OFFSET : _TICKET_TITLE_ID_OFFSET + _TICKET_TITLE_ID_SIZE
    ]
    iv = title_id + b"\x00" * (_AES_BLOCK - _TICKET_TITLE_ID_SIZE)
    return aes128_cbc_decrypt(common_key, iv, enc_title_key)


class _DecryptedPartitionSource:
    """A lazy ``ByteSource`` over the decrypted cluster payloads.

    The decrypted view has size ``cluster_count * _CLUSTER_PAYLOAD_SIZE``.
    Reads are served cluster-by-cluster: the relevant clusters' hash headers
    and ciphertext payloads are read from the parent source, decrypted with
    the title key + per-cluster IV, and the requested byte range is sliced
    out. A small bounded LRU cache of recently-decrypted payloads keeps
    sequential scans cheap without materializing the whole partition.
    """

    def __init__(self, parent: ByteSource, data_offset: int, title_key: bytes) -> None:
        self._parent = parent
        self._data_offset = data_offset
        self._title_key = title_key
        # Bounded payload cache: at most a few clusters, so peak RSS stays in
        # the low MB regardless of partition size (memory-discipline gate).
        self._cache: dict[int, bytes] = {}
        self._cache_order: list[int] = []
        self._cache_cap = 4
        parent_size = parent.size()
        region_end = data_offset + (
            (parent_size - data_offset) // _CLUSTER_SIZE * _CLUSTER_SIZE
        )
        self._cluster_count = (region_end - data_offset) // _CLUSTER_SIZE
        self._size = self._cluster_count * _CLUSTER_PAYLOAD_SIZE

    def _decrypt_cluster(self, index: int) -> bytes:
        cached = self._cache.get(index)
        if cached is not None:
            return cached
        cluster_off = self._data_offset + index * _CLUSTER_SIZE
        # Hash header (0x400) holds the IV; payload (0x7C00) is the ciphertext.
        header = self._parent.read_at(cluster_off, _CLUSTER_HASH_SIZE)
        iv = header[_CLUSTER_IV_OFFSET : _CLUSTER_IV_OFFSET + _CLUSTER_IV_SIZE]
        ciphertext = self._parent.read_at(
            cluster_off + _CLUSTER_HASH_SIZE, _CLUSTER_PAYLOAD_SIZE
        )
        plaintext = aes128_cbc_decrypt(self._title_key, iv, ciphertext)
        self._cache[index] = plaintext
        self._cache_order.append(index)
        if len(self._cache_order) > self._cache_cap:
            evict = self._cache_order.pop(0)
            self._cache.pop(evict, None)
        return plaintext

    def read_at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self._size:
            raise ValueError(
                f"read [{offset}, {offset + size}) out of bounds "
                f"(decrypted size {self._size})"
            )
        out = bytearray()
        pos = offset
        end = offset + size
        while pos < end:
            cluster_index = pos // _CLUSTER_PAYLOAD_SIZE
            in_cluster = pos % _CLUSTER_PAYLOAD_SIZE
            take = min(_CLUSTER_PAYLOAD_SIZE - in_cluster, end - pos)
            payload = self._decrypt_cluster(cluster_index)
            out += payload[in_cluster : in_cluster + take]
            pos += take
        return bytes(out)

    def size(self) -> int:
        return self._size

    def close(self) -> None:
        self._cache.clear()
        self._cache_order.clear()


def normalize_wii_partition(source) -> ByteView:
    """Decrypt one Wii partition slice into a lazy ``ByteView`` of payloads.

    ``source`` is a path or ``ByteSource`` over a raw Wii partition (the byte
    range ``wii-disc`` exposes as e.g. ``partition-data.bin``). The returned
    ``ByteView`` reads decrypted 0x7C00-byte cluster payloads on demand.
    """
    src = source if isinstance(source, ByteSource) else FileSource(source)
    common_key = _load_common_key()
    data_offset, _data_size = _parse_partition_data_region(src)
    title_key = _derive_title_key(src, common_key)
    # The common key and title key live only in this stack frame and the
    # decoded source; neither is persisted or logged. The common-key file on
    # disk is the operator's to manage (docs/WII-KEYED-WORK.md).
    decoded = _DecryptedPartitionSource(src, data_offset, title_key)
    return ByteView(source=decoded, format="wii-partition")


# Convenience for caller-composed tests: take a wii-disc FileTree + entry and
# produce the ByteView over that one partition. Not part of the frozen
# contract surface; the documented composition is normalize(view.source, ...).
def from_wii_disc_entry(tree, entry) -> ByteView:
    """Decrypt one ``wii-disc`` partition entry into a ``ByteView``."""
    return normalize_wii_partition(SliceSource(tree.source, entry.offset, entry.size))
