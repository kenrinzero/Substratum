#!/usr/bin/env python3
"""Author a synthetic encrypted Wii partition with a generated test key.

The runtime ``wii-partition`` normalizer decrypts retail partitions with the
operator-supplied standard Wii common key. That path can only be exercised
when ``fixtures/_local/wii-common-key.bin`` is present (gitignored, never
committed). This seedtool builds a *separate*, fully-committable synthetic
fixture that proves the decrypt path end-to-end with a generated 16-byte test
key — no retail key, no retail bytes.

It constructs a minimal Wii partition byte image:
  - a ticket at offset 0 whose encrypted title key decrypts (under the
    generated common key) to a known title key;
  - a partition header at 0x2C0...0x2BF pointing the data region at 0x20000;
  - N clusters of encrypted payload, each a known plaintext (a repeating
    pattern with the cluster index embedded, so wrong slicing is caught).

The synthetic common key and title key are generated deterministically from a
fixed seed and committed in plain text — they are throwaway test values, not
the retail Wii key. The runtime loader is NOT used here; this tool encrypts
with ``substratum._aes`` directly so the fixture is independent of the
normalizer under test (the normalizer only decrypts).

Usage:
    uv run python seedtools/make_wii_partition_fixture.py
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from substratum._aes import aes128_cbc_encrypt  # noqa: E402

OUTPUT = ROOT / "fixtures" / "wii_partition" / "synthetic"
CLUSTER_COUNT = 8
# Layout constants — mirror the normalizer and wiibrew spec.
_TICKET_SIZE = 0x2A4
_PARTITION_HEADER_OFF = 0x2C0  # header lives inside the ticket region's tail
_HEADER_SIZE = 0x2C0
_DATA_OFFSET = 0x20000
_CLUSTER_SIZE = 0x8000
_CLUSTER_HASH_SIZE = 0x400
_CLUSTER_PAYLOAD_SIZE = 0x7C00
_CLUSTER_IV_OFFSET = 0x3D0
_TICKET_TITLE_KEY_OFFSET = 0x1BF
_TICKET_TITLE_ID_OFFSET = 0x1DC
_TICKET_COMMON_KEY_INDEX_OFFSET = 0x1F1

# Generated test key material (NOT the retail Wii key). Deterministic, public.
_TEST_COMMON_KEY = bytes.fromhex("0123456789abcdef0123456789abcdef")
_TEST_TITLE_KEY = bytes.fromhex("fedcba9876543210fedcba9876543210")
_TEST_TITLE_ID = bytes.fromhex("0001000051544554")  # "QUTE" game code


def _make_cluster_payload(index: int) -> bytes:
    """Known plaintext for cluster ``index``: a repeating 32-byte block that
    encodes the cluster index, so any slicing/decryption error is caught by
    a single byte mismatch rather than a uniform-blob accident."""
    block = struct.pack(">II", index, 0xDEADBEEF) + b"SYNTHETIC-WII-PARTITION!"[:24]
    assert len(block) == 32
    full = b""
    while len(full) < _CLUSTER_PAYLOAD_SIZE:
        full += block
    return full[:_CLUSTER_PAYLOAD_SIZE]


def _build() -> bytes:
    total_size = _DATA_OFFSET + CLUSTER_COUNT * _CLUSTER_SIZE
    image = bytearray(total_size)

    # --- Ticket (offset 0) --------------------------------------------------
    # Signature type RSA-2048 SHA-256 (0x00010001) so the sniffer accepts it.
    struct.pack_into(">I", image, 0, 0x00010001)
    # Title ID at 0x1DC; common key index 0 at 0x1F1.
    image[_TICKET_TITLE_ID_OFFSET : _TICKET_TITLE_ID_OFFSET + 8] = _TEST_TITLE_ID
    image[_TICKET_COMMON_KEY_INDEX_OFFSET] = 0
    # Encrypt the test title key with the test common key under IV = titleID+zeros.
    title_iv = _TEST_TITLE_ID + b"\x00" * 8
    enc_title_key = aes128_cbc_encrypt(
        _TEST_COMMON_KEY, title_iv, _TEST_TITLE_KEY
    )
    image[
        _TICKET_TITLE_KEY_OFFSET : _TICKET_TITLE_KEY_OFFSET + 16
    ] = enc_title_key

    # --- Partition header fields at 0x2B8/0x2BC (data offset/size in words) -
    # The partition header the normalizer reads sits at partition offset 0;
    # its data-region fields live at 0x2B8/0x2BC. We write them in-band.
    struct.pack_into(">I", image, 0x2B8, _DATA_OFFSET // 4)
    struct.pack_into(">I", image, 0x2BC, (CLUSTER_COUNT * _CLUSTER_SIZE) // 4)

    # --- Encrypted clusters -------------------------------------------------
    for index in range(CLUSTER_COUNT):
        base = _DATA_OFFSET + index * _CLUSTER_SIZE
        # Hash header: put a recognizable per-cluster IV at 0x3D0 (the rest is
        # zero, which is fine — we do not verify the hash tree, only the decrypt).
        iv = struct.pack(">I", index) + b"\xAA" * 12
        image[base + _CLUSTER_IV_OFFSET : base + _CLUSTER_IV_OFFSET + 16] = iv
        payload = _make_cluster_payload(index)
        ciphertext = aes128_cbc_encrypt(_TEST_TITLE_KEY, iv, payload)
        image[
            base + _CLUSTER_HASH_SIZE : base + _CLUSTER_HASH_SIZE + _CLUSTER_PAYLOAD_SIZE
        ] = ciphertext
    return bytes(image)


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    image = _build()
    partition_path = OUTPUT / "partition.bin"
    partition_path.write_bytes(image)
    # Commit the generated test key + expected plaintext descriptor so the
    # test can derive truth independently of the normalizer.
    key_path = OUTPUT / "test-common-key.bin"
    key_path.write_bytes(_TEST_COMMON_KEY)
    # write_bytes, not write_text: write_text maps \n to the platform newline,
    # so on this Windows host it silently emitted a CRLF descriptor.
    (OUTPUT / "clusters.json").write_bytes(
        (
            '{"cluster_count": %d, "payload_size": %d, '
            '"test_title_id": "%s"}\n'
            % (
                CLUSTER_COUNT,
                _CLUSTER_PAYLOAD_SIZE,
                _TEST_TITLE_ID.hex(),
            )
        ).encode("ascii")
    )
    print(
        f"authored synthetic Wii partition: {len(image)} bytes, "
        f"{CLUSTER_COUNT} clusters\n"
        f"  partition  -> {partition_path}\n"
        f"  test key   -> {key_path} (generated; NOT the retail Wii key)\n"
        f"  descriptor -> {OUTPUT / 'clusters.json'}"
    )


if __name__ == "__main__":
    main()
