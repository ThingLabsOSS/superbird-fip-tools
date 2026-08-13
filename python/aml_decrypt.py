"""Amlogic G12A FIP / DTB partition decryptor (legacy Python path).

Decrypts Amlogic-signed blobs with Spotify's leaked production key, for static
analysis of vendor BL33 / DTB / kernel images. See `-h` for the input modes.

The maintained implementation is `fip-tool decrypt`; this is kept for
reference and cross-checking.

Non-obvious bits:

  - The AES-256 key is at offsets 0x1173 and 0x1B20 inside `aml-user-key.sig`
    (redundant copies) and is re-extracted on every run, so the tool stays
    self-contained against the key file. How those offsets were found:
    ../docs/secure-boot.md.

  - Amlogic's per-section "IV reset" only affects the first 16-byte block at
    each sub-section boundary. That block is the section's MAC slot and
    decodes as noise, so nothing useful is lost by ignoring it.

  - The DTB area carries a CRC32 footer and may have an RSA signature
    appended (vendor's `Sig Check 1497` path). Only the plaintext matters
    here; the signature is not verified.

Not handled: **BL33 LZ4 decompression.** Vendor BL33 is LZ4-compressed inside
the AES envelope in Amlogic's "LZ4C" container — no standard frame magic, but
it does unpack statically. Use the Go tool:
`fip-tool decrypt -bootloader -bl33 -o u-boot.bin bootloader.dump`
(format in `fip-tool/lz4unwrap.go`).
"""
import argparse
import struct
import sys
from pathlib import Path
from Crypto.Cipher import AES

# keys/ lives at the repo root; this script now lives in python/.
DEFAULT_KEY_PATH = Path(__file__).resolve().parent.parent / "keys" / "aml-user-key.sig"

# Known-good AES-256 key fingerprint (also burned into BL2 by Spotify's signing
# tooling). Used as a sanity check when extracting from a keybundle.
EXPECTED_KEY_HEX = (
    "ab6541be131018f71fbc266f4643ff0d"
    "7626f9ab4ee2077ab7fd63dc620c090d"
)

# Where the AES key lives inside aml-user-key.sig (Spotify's bundle). The key
# is duplicated at both offsets — we verify they match.
KEY_OFFSETS = (0x1173, 0x1B20)
KEY_SIZE = 32


def extract_aes_key(keybundle_path: Path) -> bytes:
    """Pull the AES-256 key out of a Spotify-style aml-user-key.sig bundle.

    Verifies the two redundant copies (offsets 0x1173 and 0x1B20) agree, and
    cross-checks against the known production-key fingerprint. Raises
    ValueError on mismatch — there's no useful fallback if the bundle layout
    differs."""
    data = keybundle_path.read_bytes()
    if len(data) < KEY_OFFSETS[-1] + KEY_SIZE:
        raise ValueError(
            f"keybundle {keybundle_path} too small ({len(data)} bytes); "
            f"expected at least {KEY_OFFSETS[-1] + KEY_SIZE}"
        )
    candidates = [data[off:off + KEY_SIZE] for off in KEY_OFFSETS]
    if candidates[0] != candidates[1]:
        raise ValueError(
            "redundant AES key copies at 0x1173 and 0x1B20 do not match; "
            "is this a non-Spotify bundle?"
        )
    key = candidates[0]
    if key.hex() != EXPECTED_KEY_HEX:
        # Not necessarily fatal — different firmware vintages could theoretically
        # use a different production key — but worth flagging loudly.
        print(
            f"warning: extracted key {key.hex()} does not match the "
            f"known production key fingerprint. Proceeding anyway.",
            file=sys.stderr,
        )
    return key


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes = b"\x00" * 16) -> bytes:
    """AES-256-CBC decrypt with a fixed IV. Length must be a multiple of 16."""
    if len(ciphertext) % 16 != 0:
        # Round down to last full block — the trailing partial block (if any)
        # is just padding from the eMMC partition / FIP container.
        ciphertext = ciphertext[: (len(ciphertext) // 16) * 16]
    return AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext)


# ---- FIP body parsing -----------------------------------------------------

# Layout (per FIP_NOTES.md):
#   bootloader (4 MiB) :  BL2 (0x10000)  +  FIP body (~1.2 MiB)  +  zero pad
#
# The FIP body itself contains:
#   0x00000 - 0x04000   FIP HDR (16 KiB: entry table + signatures)
#   0x04000 - 0x5C000   per-entry headers, DDR firmware, RSA sigs
#   0x05C000 - 0x130000 BL3X blob (~848 KiB: BL30 + BL31 + BL32 + BL33)
FIP_BODY_OFFSET_IN_BOOTLOADER = 0x10000


def detect_input_kind(data: bytes) -> str:
    """Heuristic — figure out what flavour of Amlogic blob this is."""
    if len(data) >= FIP_BODY_OFFSET_IN_BOOTLOADER + 16:
        # A 4 MiB bootloader.dump should have a recognizable BL2 header at
        # offset 0 (the encrypted BL2 starts with non-zero ciphertext, but
        # the FIP body at 0x10000 starts predictably with 16 zero bytes
        # encrypted to the well-known C[0]).
        expected_c0 = bytes.fromhex("16dcfdb77c39ac15998ddbcf8c4132cc")
        if data[FIP_BODY_OFFSET_IN_BOOTLOADER:FIP_BODY_OFFSET_IN_BOOTLOADER + 16] == expected_c0:
            return "bootloader_dump"
    if len(data) >= 16:
        # Standalone fip_a / fip_b partition: starts directly with the FIP body.
        expected_c0 = bytes.fromhex("16dcfdb77c39ac15998ddbcf8c4132cc")
        if data[:16] == expected_c0:
            return "fip_body"
    return "raw"


def decrypt_fip(data: bytes, key: bytes, source_kind: str) -> bytes:
    """Decrypt a FIP body (or bootloader.dump containing one) end-to-end.

    Returns the plaintext FIP body. The BL2 prefix (if present) is not
    decrypted — BL2 is verified+decrypted by the SoC mask ROM with a fused
    key, not this user key."""
    if source_kind == "bootloader_dump":
        fip_ct = data[FIP_BODY_OFFSET_IN_BOOTLOADER:]
    elif source_kind == "fip_body":
        fip_ct = data
    else:
        raise ValueError(f"can't FIP-decrypt source_kind={source_kind}")
    return decrypt_cbc(fip_ct, key)


def map_fip_sections(pt: bytes):
    """Yield (offset, length, label) tuples for major regions of a decrypted
    FIP body.

    The Amlogic FIP format on G12A has an outer envelope (HDR at 0..0x4000),
    a per-entry/DDR-firmware area (0x4000..0x5C000), and a BL3X blob
    (0x5C000..). Each component is announced by an "@AML" magic at a
    16-byte-aligned offset. We hunt for those magics and report the spans
    between them; the caller can then carve sub-sections out for further
    analysis.

    This is intentionally a structure SUMMARY, not a full parser — the
    exact entry-table format hasn't been formally documented and varies
    subtly across firmware vintages, so a robust parser would be premature.
    The @AML-anchor approach is firmware-vintage-agnostic.
    """
    import re
    AML_MAGIC = b"@AML"
    # Real @AML headers always sit at 16-byte alignment (AES-CBC block
    # boundary). Filter out spurious matches inside random data.
    anchors = sorted(
        m.start() for m in re.finditer(AML_MAGIC, pt) if m.start() % 16 == 0
    )
    if not anchors:
        return

    def label_for(offset, length):
        if offset == 0x10:
            return "FIP HDR (entry table + sigs)"
        if 0x4000 <= offset < 0x5C000:
            return "per-entry metadata / DDR fw / sigs"
        if offset == 0x5C010:
            return "BL3X TOC"
        if 0x5C000 <= offset < 0x70000:
            return "BL30 (SCP)"
        if 0x70000 <= offset < 0x98000:
            return "BL31 (TF-A) or BL32 (BL31 first on G12A)"
        if 0x98000 <= offset < 0x130000:
            return "BL33 (u-boot, LZ4-compressed)"
        return "data"

    for i, off in enumerate(anchors):
        next_off = anchors[i + 1] if i + 1 < len(anchors) else len(pt)
        yield off, next_off - off, label_for(off, next_off - off)


# ---- DTB partition parsing ------------------------------------------------

def decrypt_dtb_partition(data: bytes, key: bytes) -> bytes:
    """Decrypt a raw DTB partition dump (typically 256 KiB read via
    `emmc dtb_read 0x1000000 0x40000`).

    Vendor u-boot's `_verify_dtb_checksum()` expects two redundant copies
    (cpy 0 and cpy 1) at known offsets within the 256 KiB area, each with
    a CRC32 footer. We just decrypt the whole region and let the caller
    locate the FDT magic inside; that's friendlier when partition layouts
    drift across firmware versions."""
    return decrypt_cbc(data, key)


def find_fdt_blobs(pt: bytes, min_size: int = 0x100, max_size: int = 0x80000):
    """Locate every plausible FDT (device tree blob) inside a plaintext buffer.

    Looks for magic 0xD00DFEED (big-endian on the wire) and validates the
    totalsize / version fields against typical bounds. Yields (offset,
    totalsize) tuples sorted by offset."""
    import re
    for m in re.finditer(b"\xd0\x0d\xfe\xed", pt):
        off = m.start()
        if off + 24 > len(pt):
            continue
        totalsize = struct.unpack(">I", pt[off + 4:off + 8])[0]
        version = struct.unpack(">I", pt[off + 20:off + 24])[0]
        if min_size <= totalsize <= max_size and version in (16, 17):
            yield off, totalsize


# ---- CLI ------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(
        description="Decrypt Amlogic G12A FIP / DTB partitions using "
                    "Spotify's leaked production key.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  # decrypt a bootloader.dump (4 MiB, BL2 + FIP body)\n"
            "  aml_decrypt.py --auto bootloader.dump -o /tmp/fip.bin\n"
            "\n"
            "  # decrypt a standalone fip_a partition\n"
            "  aml_decrypt.py --fip fip_a.dump -o /tmp/fip.bin\n"
            "\n"
            "  # decrypt a DTB partition dump + extract FDTs from it\n"
            "  aml_decrypt.py --dtb dtb_partition.bin -o /tmp/dtbs.bin\n"
            "\n"
            "  # raw AES-256-CBC zero-IV decrypt of any blob\n"
            "  aml_decrypt.py --raw blob.enc -o blob.bin\n"
        ),
    )
    p.add_argument("input", help="encrypted file to decrypt")
    p.add_argument("-o", "--output", required=True,
                   help="output file for plaintext")
    p.add_argument("-k", "--keybundle", default=str(DEFAULT_KEY_PATH),
                   help=f"path to aml-user-key.sig (default: {DEFAULT_KEY_PATH})")
    p.add_argument("--show-key", action="store_true",
                   help="print the extracted key and exit")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--auto", action="store_true",
                      help="auto-detect input type (default if no mode chosen)")
    mode.add_argument("--fip", action="store_true",
                      help="treat input as a standalone FIP body")
    mode.add_argument("--bootloader", action="store_true",
                      help="treat input as bootloader.dump (BL2 + FIP body)")
    mode.add_argument("--dtb", action="store_true",
                      help="treat input as a raw DTB partition dump")
    mode.add_argument("--raw", action="store_true",
                      help="raw AES-256-CBC zero-IV decrypt, no structure parsing")
    p.add_argument("--scan-fdts", action="store_true",
                   help="after decrypt, scan for FDT blobs and print their "
                        "offsets/sizes")
    p.add_argument("--map-sections", action="store_true",
                   help="after decrypt, print a map of major FIP sub-sections "
                        "(anchored on @AML magic)")
    args = p.parse_args(argv)

    key = extract_aes_key(Path(args.keybundle))
    if args.show_key:
        print(f"AES-256 key: {key.hex()}")
        return 0

    ct = Path(args.input).read_bytes()
    print(f"loaded {len(ct)} bytes from {args.input}", file=sys.stderr)

    kind = detect_input_kind(ct)
    if args.bootloader:
        kind = "bootloader_dump"
    elif args.fip:
        kind = "fip_body"
    elif args.dtb:
        kind = "dtb_partition"
    elif args.raw:
        kind = "raw"
    print(f"mode: {kind}", file=sys.stderr)

    if kind == "bootloader_dump" or kind == "fip_body":
        pt = decrypt_fip(ct, key, kind)
    elif kind == "dtb_partition":
        pt = decrypt_dtb_partition(ct, key)
    else:
        # raw
        pt = decrypt_cbc(ct, key)

    Path(args.output).write_bytes(pt)
    print(f"wrote {len(pt)} bytes to {args.output}", file=sys.stderr)

    if args.map_sections and kind in ("bootloader_dump", "fip_body"):
        print("\n=== FIP sub-section map (@AML anchors) ===")
        for off, length, label in map_fip_sections(pt):
            print(f"  0x{off:06x}  len=0x{length:06x}  {label}")

    if args.scan_fdts:
        print("\n=== FDT blobs in plaintext ===")
        for off, total in find_fdt_blobs(pt):
            print(f"  offset=0x{off:06x}  totalsize=0x{total:x}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
