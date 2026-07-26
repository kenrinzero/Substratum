# Deferred Wii keyed normalization

## Current boundary

Substratum 0.0.11 already normalizes the keyless outer Wii disc layer.
`wii-disc` returns opaque encrypted DATA, UPDATE, or CHANNEL partition
slices. It does not derive title keys, decrypt clusters, or walk the Wii
filesystem.

The remaining work is intentionally deferred:

1. `wii-partition` — use the standard Wii common key to derive a
   partition title key and return one lazy decrypted `ByteView`.
2. `wii-fst` — walk that decrypted view as a separate caller-composed
   `FileTree`.

Neither unit should be combined with `wii-disc`.

## Artifact required to resume

The only requested artifact is the **standard Wii common AES key**:

- exactly 16 bytes;
- raw binary, not 32 ASCII hexadecimal characters;
- common-key index 0, as used by the qualified The Munchables disc;
- not a complete BootMii `keys.bin`;
- not the console-specific NAND AES key;
- not the distinct vWii common key.

The preferred source is a BootMii NAND backup from a regular Wii you own.
BootMii writes a 1024-byte `keys.bin`; its standard common key occupies
offset `0x114` through `0x123`. WiiBrew documents that layout:
<https://wiibrew.org/wiki/BackupMii>. The alternative `xyzzy` homebrew
utility writes console keys to `SD:/keys.txt`:
<https://wiibrew.org/wiki/Xyzzy>.

Do not download, commit, paste into a log, or publish the key.

## Local extraction and storage

Copy your BootMii `keys.bin` to the PC, then run PowerShell with the source
path adjusted:

```powershell
$source = "D:\keys.bin"
$destination = "C:\Users\kenrin\Project\Substratum\fixtures\_local\wii-common-key.bin"

$keys = [System.IO.File]::ReadAllBytes($source)
if ($keys.Length -lt 0x124) {
    throw "keys.bin is too short or has the wrong format."
}

$commonKey = $keys[0x114..0x123]
[System.IO.File]::WriteAllBytes($destination, $commonKey)

(Get-Item -LiteralPath $destination).Length
```

The final command must print `16`. The `_local` directory is already
gitignored.

For the current PowerShell session, point Substratum at the file without
printing its contents:

```powershell
$env:SUBSTRATUM_WII_COMMON_KEY_FILE = "C:\Users\kenrin\Project\Substratum\fixtures\_local\wii-common-key.bin"
```

Do not record the key or its digest in manifests, tests, terminal
transcripts, Atelier, or error messages. Code should report only whether
the file exists and is exactly 16 bytes.

## Resume checklist

When `fixtures/_local/wii-common-key.bin` exists:

1. Confirm only its length, never its contents.
2. Take `wii-partition` as one normalizer session.
3. Keep runtime crypto stdlib-only and lazy/bounded.
4. Anchor AES-CBC mechanics with public NIST vectors and a generated
   synthetic Wii partition using a generated test key.
5. Run conditional retail proof against the encrypted partition slices
   from The Munchables, with pinned wit as the independent oracle.
6. Commit no key bytes or decrypted retail payloads.
7. Take `wii-fst` only afterward, in its own session.

Until then, both keyed Wii units remain deferred and Substratum itself is
cleanly usable through the eleven GREEN keyless/decrypted normalizers.
