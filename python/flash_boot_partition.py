#!/usr/bin/env python3
"""
flash_boot_partition.py — write a complete bootloader image (info_sector +
BL2 + FIP) to a Spotify Car Thing's eMMC boot0/boot1 hardware partitions,
following Amlogic G12A vendor conventions.

When paired with a FIP body re-signed via the leaked aml-user-key.sig
production key, this lets us boot upstream/custom u-boot at power-on
without ever running vendor BL33.

Modes:
  ours  - build hybrid: stock BL2 (unchanged) + our re-signed FIP body
          and flash it. Requires --signed-fip pointing at a
          ./out/u-boot.bin.spotify.encrypt produced by ./fip-rebuild.sh.
  stock - rebuild and flash a known-stock bootloader (recovery).
          Uses --stock-bootloader (defaults to the in-repo
          stock.bootloader.bin, 4 MiB).
  raw   - flash an arbitrary 2_097_152-byte image (1 sector info_sector
          + 4095 sectors of bootloader content) verbatim.

The device must be in USB Burn Mode (1b8e:c003 after `superbird-tool
--burn_mode`).

Recovery: in case of trouble, mask ROM USB Mode always works.
Hold buttons 1+4 + reset, then `superbird-tool --burn_mode`, then
`flash_boot_partition.py stock` (uses the in-repo stock.bootloader.bin).

Author: ThingLabsOSS / superbird-fip-tools. MIT licensed.
"""
import argparse
import os
import struct
import sys
import time

# Repo root — the shipped stock.bootloader.bin and out/ live one level up,
# since this script now lives in python/.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# === Constants from spsgsb/uboot include/emmc_partitions.h ===
# These describe where Amlogic vendor lays out user-area partitions on
# the Car Thing. We don't need most of them; only DDR-init params and
# the reserved-area base address.
MMC_RESERVED_OFFSET  = 36 * 1024 * 1024   # 0x02400000 — start of reserved region
DDR_PARAMETER_OFFSET = 8  * 1024 * 1024   # relative to reserved
DDR_PARAMETER_SIZE   = 4 * 512            # 0x800 bytes
INFO_SECTOR_SIZE     = 512
# Image is exactly 2 MiB total (info_sector + 2 MiB - 512 B of BL2+FIP).
# 2 MiB is a hard ceiling, not a comfortable target: boot partition size
# varies by fitted eMMC part. Measured across seven field units, every
# Samsung S40004 has 4 MiB boot partitions (BOOT_SIZE_MULT=32) and every
# Kioxia 004GA0 has exactly 2 MiB (BOOT_SIZE_MULT=16). One sector beyond
# 2 MiB is therefore fine on half the fleet and fatal on the other half:
#   `MMC: block number 0x1001 exceeds max(0x1000)`.
# If the image ever needs to grow, it breaks Kioxia units only — which
# is the most annoying possible failure mode, so don't.
# Actual BL2 + FIP content is only ~1.3 MiB; the tail is zero pad.
BOOTLOADER_CONTENT_SIZE = 2 * 1024 * 1024 - INFO_SECTOR_SIZE  # = 4095 sectors
TOTAL_SECTORS = (INFO_SECTOR_SIZE + BOOTLOADER_CONTENT_SIZE) // 512  # 4096
DRAM_STAGING_ADDR = 0x13000000

# Amlogic USB IDs
AML_USB_BURN_VID = 0x1b8e
AML_USB_BURN_PID = 0xc003


def make_info_sector():
    """Build the storage_emmc_boot_info struct that goes at LBA 0 of
    boot0 and boot1, byte-identical to the vendor's
    amlmmc_write_info_sector().

    The ddr.addr/ddr.size fields nominally point BL2 at DDR-init
    parameters in the user area's reserved region. On our GPT layout
    there is no reserved region — rsv_base 0x12000 + ddr.addr 0x4000
    is LBA 0x16000, which is inside boot_a — so BL2 has been reading
    our FAT filesystem as "DDR timing" on every boot, harmlessly.

    Verified on hardware 2026-08-12: zeroing ddr.addr and ddr.size on
    *both* boot0 and boot1 (checksum recomputed) boots to Linux
    normally. BL2 does not consume them; the timings that actually run
    are compiled into BL2 itself (vendor firmware/timing.c). We keep
    the vendor values regardless, so the sector stays identical to a
    stock one and `stock` mode restores a layout where the reserved
    region really does exist.

    Layout (from spsgsb/uboot include/amlogic/aml_mmc.h):

        u32 version;          // offset 0
        u32 rsv_base_addr;    // offset 4   (sectors)
        u32 dtb.addr;         // offset 8   (vendor leaves 0)
        u32 dtb.size;         // offset 12
        u32 ddr.addr;         // offset 16  (sectors, relative to reserved)
        u32 ddr.size;         // offset 20  (sectors)
        u8  reserved[...];    // offset 24..507
        u32 checksum;         // offset 508 (sum of u32s at indices 0..126)
    """
    buf = bytearray(INFO_SECTOR_SIZE)
    struct.pack_into('<IIIIII', buf, 0,
        1,                                # version
        MMC_RESERVED_OFFSET // 512,       # rsv_base_addr = 0x12000
        0, 0,                             # dtb.addr/size — vendor leaves zero
        DDR_PARAMETER_OFFSET // 512,      # ddr.addr = 0x4000 (relative)
        DDR_PARAMETER_SIZE // 512,        # ddr.size = 0x4 sectors
    )
    checksum = 0
    for i in range(127):  # u32s at indices 0..126; checksum at index 127
        checksum = (checksum + struct.unpack_from('<I', buf, i * 4)[0]) & 0xffffffff
    struct.pack_into('<I', buf, 127 * 4, checksum)
    return bytes(buf)


def build_image_ours(stock_bootloader_path, signed_fip_path):
    """Stock BL2 (first 64 KiB of the stock bootloader) + our re-signed FIP
    body (signed_fip_path[0x10000:]), padded to 2 MiB. Plus info_sector at
    LBA 0.
    """
    info = make_info_sector()
    with open(stock_bootloader_path, 'rb') as f:
        stock_bl2 = f.read(0x10000)
    if len(stock_bl2) != 0x10000:
        raise SystemExit(f'stock-bootloader is too small (need ≥64 KiB): {stock_bootloader_path}')
    with open(signed_fip_path, 'rb') as f:
        f.seek(0x10000)
        fip_body = f.read()
    content = stock_bl2 + fip_body
    if len(content) > BOOTLOADER_CONTENT_SIZE:
        raise SystemExit(f'BL2+FIP exceeds 2 MiB: {len(content)} bytes. Reduce u-boot size or expand layout.')
    content = content + b'\x00' * (BOOTLOADER_CONTENT_SIZE - len(content))
    return info + content


def build_image_stock(stock_bootloader_path):
    """Unmodified stock content + info_sector (for recovery flashes)."""
    info = make_info_sector()
    with open(stock_bootloader_path, 'rb') as f:
        content = f.read(BOOTLOADER_CONTENT_SIZE)
    if len(content) < BOOTLOADER_CONTENT_SIZE:
        content += b'\x00' * (BOOTLOADER_CONTENT_SIZE - len(content))
    return info + content


def build_image_raw(raw_path):
    with open(raw_path, 'rb') as f:
        img = f.read()
    expected = INFO_SECTOR_SIZE + BOOTLOADER_CONTENT_SIZE
    if len(img) != expected:
        raise SystemExit(f'raw image must be exactly {expected} bytes, got {len(img)}')
    return img


def flash(image_bytes, hwparts=(1, 2), dry_run=False):
    """Upload image to DRAM, then `mmc write` to each requested hwpart at LBA 0.

    hwpart 1 = boot0, hwpart 2 = boot1, hwpart 0 = user area (not used here).
    Stock writes both 1 and 2 for redundancy.
    """
    if dry_run:
        print(f'[dry-run] would upload {len(image_bytes)} bytes to DRAM 0x{DRAM_STAGING_ADDR:08x}')
        for hwp in hwparts:
            print(f'[dry-run] would mmc dev 1 {hwp} ; mmc write 0x{DRAM_STAGING_ADDR:08x} 0 0x{TOTAL_SECTORS:04x}')
        print('[dry-run] would mmc dev 1 0 (restore user-area access)')
        return

    try:
        from pyamlboot import pyamlboot
    except ImportError:
        raise SystemExit(
            'pyamlboot not installed.\n'
            '  sudo python3 -m pip install git+https://github.com/superna9999/pyamlboot\n'
            'Or use a venv that has it (e.g. ../superbird-tool/venv).'
        )

    print(f'opening Amlogic burn-mode device (VID/PID {AML_USB_BURN_VID:04x}:{AML_USB_BURN_PID:04x})...')
    dev = pyamlboot.AmlogicSoC()

    def bulk(cmd):
        print(f'  bulkcmd: {cmd}')
        resp = dev.bulkCmd(cmd)
        result = resp.tobytes().decode('utf-8', errors='replace').strip()
        # Vendor burn-mode protocol pads results with spaces; trim.
        if 'fail' in result.lower():
            raise RuntimeError(f'bulkcmd failed: {cmd} -> {result}')

    print(f'uploading {len(image_bytes)} bytes to DRAM 0x{DRAM_STAGING_ADDR:08x}...')
    # pyamlboot.writeLargeMemory chunks for us.
    dev.writeLargeMemory(DRAM_STAGING_ADDR, image_bytes)

    for hwp in hwparts:
        label = {1: 'boot0', 2: 'boot1', 0: 'user'}.get(hwp, f'hwpart{hwp}')
        print(f'writing to {label} (hwpart {hwp}):')
        bulk(f'mmc dev 1 {hwp}')
        bulk(f'mmc write 0x{DRAM_STAGING_ADDR:08x} 0 0x{TOTAL_SECTORS:04x}')

    # always restore user-area access so subsequent reads/writes go to user
    print('restoring active hwpart to user area:')
    bulk('mmc dev 1 0')
    time.sleep(0.5)
    print('DONE — power-cycle or RTS-reset to see effect')


def main():
    p = argparse.ArgumentParser(
        description=__doc__.strip().split('\n\n')[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.strip().split('\n\n', 1)[1],
    )
    p.add_argument('mode', choices=['ours', 'stock', 'raw'],
                   help='what kind of boot image to build and flash')
    p.add_argument('--stock-bootloader', default=os.path.join(REPO_ROOT, 'stock.bootloader.bin'),
                   help='path to the stock bootloader image (default: the in-repo stock.bootloader.bin). Used by `ours` and `stock` modes.')
    p.add_argument('--signed-fip', default=os.path.join(REPO_ROOT, 'out', 'u-boot.bin.spotify.encrypt'),
                   help='path to fip-rebuild.sh output (default: <repo>/out/u-boot.bin.spotify.encrypt). Used by `ours` mode.')
    p.add_argument('--raw-image', default=None,
                   help='path to a pre-built 2_097_152-byte boot partition image. Required for `raw` mode.')
    p.add_argument('-o', '--output-image', default=None,
                   help='also save the built image to this path (useful for inspection)')
    p.add_argument('--boot0-only', action='store_true',
                   help='only flash boot0 (hwpart 1); skip boot1 (hwpart 2)')
    p.add_argument('--boot1-only', action='store_true',
                   help='only flash boot1 (hwpart 2); skip boot0 (hwpart 1)')
    p.add_argument('--dry-run', action='store_true',
                   help='build the image but do not write to device')
    args = p.parse_args()

    if args.mode == 'ours':
        img = build_image_ours(args.stock_bootloader, args.signed_fip)
    elif args.mode == 'stock':
        img = build_image_stock(args.stock_bootloader)
    elif args.mode == 'raw':
        if not args.raw_image:
            raise SystemExit('raw mode requires --raw-image PATH')
        img = build_image_raw(args.raw_image)

    print(f'built image: {len(img)} bytes ({INFO_SECTOR_SIZE} B info_sector + {len(img) - INFO_SECTOR_SIZE} B bootloader content)')

    if args.output_image:
        with open(args.output_image, 'wb') as f:
            f.write(img)
        print(f'saved to {args.output_image}')

    if args.boot0_only and args.boot1_only:
        raise SystemExit('--boot0-only and --boot1-only are mutually exclusive')
    if args.boot0_only:
        hwparts = (1,)
    elif args.boot1_only:
        hwparts = (2,)
    else:
        hwparts = (1, 2)

    flash(img, hwparts=hwparts, dry_run=args.dry_run)


if __name__ == '__main__':
    main()
