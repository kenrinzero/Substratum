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
import tempfile
import weakref
from pathlib import Path

from substratum._aes import (
    aes128_cbc_decrypt,
    cbc_decrypt_blocks,
    expand_key,
)
from substratum.contract import ByteSource, ByteView, FileSource, SliceSource

__all__ = ["sniff", "normalize_wii_partition", "materialize"]

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
    Reads decrypt **only the AES blocks they cover**: CBC decryption chains
    through ciphertext (which is always readable), so the blocks a read needs
    are exactly its own plus the one preceding block as the XOR IV — the
    cluster header IV at 0x3D0 seeds only block 0 of each cluster. The title
    key never changes, so the key schedule is expanded once per source.
    This is what took a 1-read-per-file census over Mario Kart Wii's 2007
    files from ~133 s (whole-cluster decrypt per read) to single-digit
    seconds (BACKLOG "Wii partition read performance", 2026-08-14).
    """

    def __init__(self, parent: ByteSource, data_offset: int, title_key: bytes) -> None:
        self._parent = parent
        self._data_offset = data_offset
        self._round_keys = expand_key(title_key)  # one schedule per partition
        parent_size = parent.size()
        region_end = data_offset + (
            (parent_size - data_offset) // _CLUSTER_SIZE * _CLUSTER_SIZE
        )
        self._cluster_count = (region_end - data_offset) // _CLUSTER_SIZE
        self._size = self._cluster_count * _CLUSTER_PAYLOAD_SIZE

    def _read_span(self, index: int, start: int, length: int) -> bytes:
        """Decrypt ``payload[start : start + length]`` of cluster ``index``."""
        first = start // _AES_BLOCK
        last = (start + length + _AES_BLOCK - 1) // _AES_BLOCK
        cluster_off = self._data_offset + index * _CLUSTER_SIZE
        if first == 0:
            # Block 0 chains from the cluster's own IV (hash header 0x3D0).
            # The IV and the ciphertext (header end 0x400) sit in one
            # contiguous parent range with 0x30 bytes of header between.
            raw = self._parent.read_at(
                cluster_off + _CLUSTER_IV_OFFSET,
                _CLUSTER_HASH_SIZE - _CLUSTER_IV_OFFSET + last * _AES_BLOCK,
            )
            iv = raw[:_CLUSTER_IV_SIZE]
            ciphertext = raw[_CLUSTER_HASH_SIZE - _CLUSTER_IV_OFFSET :]
        else:
            # Later blocks chain from the preceding ciphertext block.
            ciphertext = self._parent.read_at(
                cluster_off + _CLUSTER_HASH_SIZE + (first - 1) * _AES_BLOCK,
                (last - first + 1) * _AES_BLOCK,
            )
            iv = ciphertext[:_AES_BLOCK]
            ciphertext = ciphertext[_AES_BLOCK:]
        plaintext = cbc_decrypt_blocks(self._round_keys, iv, ciphertext)
        skip = start - first * _AES_BLOCK
        return plaintext[skip : skip + length]

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
            out += self._read_span(cluster_index, in_cluster, take)
            pos += take
        return bytes(out)

    def size(self) -> int:
        return self._size

    def close(self) -> None:
        # Nothing is cached anymore — reads decrypt exactly their own blocks,
        # so there is no state to release. Kept for API compatibility with
        # the previously cached implementation.
        return None


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


class MaterializedPartition:
    """A decrypt-once spool: the whole partition decrypted to a local temp
    file, served as plain reads (BACKLOG "Wii partition read performance").

    Bulk consumers that read most of a multi-GB partition (operator-run
    sweeps, whole-partition fidelity checks) pay the AES cost exactly once
    here instead of through lazy per-read decryption, at the cost of ~4 GB
    of temp disk. ``view`` is a plain-file ``ByteView`` over the spool;
    ``close()`` deletes it (idempotent, plus a ``weakref.finalize``
    fallback); use as a context manager when possible.
    """

    def __init__(self, path: Path, view: ByteView) -> None:
        self.path = path
        self.view = view
        self._closed = False
        self._finalizer = weakref.finalize(self, self._remove, path)

    @staticmethod
    def _remove(path: Path) -> None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._finalizer()
        source = self.view.source
        closer = getattr(source, "close", None)
        if callable(closer):
            closer()

    def __enter__(self) -> "MaterializedPartition":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def materialize(source) -> MaterializedPartition:
    """Decrypt a Wii partition once into a temp-file-backed ``ByteView``.

    Accepts the same input as :func:`normalize_wii_partition` (a path or
    ``ByteSource`` over a raw partition). Returns a
    :class:`MaterializedPartition`; its ``view`` serves plain reads with no
    further decryption. Key discipline is unchanged: the title key exists
    only in memory during the spool and is never logged or persisted.
    """
    src = source if isinstance(source, ByteSource) else FileSource(source)
    common_key = _load_common_key()
    data_offset, data_size = _parse_partition_data_region(src)
    title_key = _derive_title_key(src, common_key)
    round_keys = expand_key(title_key)
    cluster_count = data_size // _CLUSTER_SIZE

    fd, spool_name = tempfile.mkstemp(prefix="substratum-wii-partition-")
    spool_path = Path(spool_name)
    try:
        with os.fdopen(fd, "wb") as spool:
            for index in range(cluster_count):
                cluster_off = data_offset + index * _CLUSTER_SIZE
                header = src.read_at(cluster_off, _CLUSTER_HASH_SIZE)
                iv = header[_CLUSTER_IV_OFFSET : _CLUSTER_IV_OFFSET + _CLUSTER_IV_SIZE]
                ciphertext = src.read_at(
                    cluster_off + _CLUSTER_HASH_SIZE, _CLUSTER_PAYLOAD_SIZE
                )
                spool.write(cbc_decrypt_blocks(round_keys, iv, ciphertext))
    except BaseException:
        spool_path.unlink(missing_ok=True)
        raise
    return MaterializedPartition(spool_path, ByteView(FileSource(spool_path), "wii-partition"))
