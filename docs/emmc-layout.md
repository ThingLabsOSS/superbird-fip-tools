# eMMC physical layout

The Car Thing's eMMC has three physically distinct partitions (eMMC
hardware concept, not Amlogic-specific):

- **boot0** (hwpart 1): 4 MiB hardware boot partition
- **boot1** (hwpart 2): 4 MiB hardware boot partition  (mask ROM
  reads from this one on shipped Car Things — see
  `PARTITION_CONFIG` below)
- **user area** (hwpart 0): 3.6 GiB user data
- **RPMB** (hwpart 3): 4 MiB authentication-guarded keys storage

`mmc dev 1 <N>` from u-boot selects hwpart N.

## boot0 / boot1 layout (G12A vendor convention)

```
LBA 0       (offset 0)        : info_sector (storage_emmc_boot_info struct, 512 B)
LBA 1       (offset 0x200)    : BL2 (signed+encrypted, 64 KiB)
LBA 129     (offset 0x10200)  : FIP HDR (16 KiB)
LBA 161     (offset 0x14200)  : per-entry headers, DDR firmware, RSA sigs
LBA 433+    (offset 0x36200+) : BL3X blob (BL30+BL31+BL32+BL33)
              ↑ exact offset varies by build; FIP HDR points at it
LBA 4096    (offset 0x200000) : end of bootloader region (zeros after)
```

### Key facts

- **Mask ROM reads BL2 starting at LBA 1**, not LBA 0. The first sector
  (info_sector) is intentionally not BL2. Mask ROM's first read attempt
  reads from LBA 0, fails the signature check, retries at LBA 1, and
  succeeds. **One `CHK:1F` in the boot tag is normal and expected.**
- **`GXL_START_BLK = 1`** in `spsgsb/uboot common/cmd_aml_mmc.c` for
  G12A and later. Older GXBB used `GXB_START_BLK = 0` (start at LBA 0).
- **boot0 and boot1 are mirrors** — vendor `amlmmc_write_bootloader`
  writes the same image to both. EXT_CSD `PARTITION_CONFIG` selects
  which one mask ROM reads from at boot.
- **PARTITION_CONFIG = 0x11** on Car Thing:
  - bits 5:3 (`BOOT_PARTITION_ENABLE`) = `0b010` = 2 → **boot1**
  - bits 2:0 (`PARTITION_ACCESS`) = `0b001` = boot0 (current user access)

## storage_emmc_boot_info (info_sector at LBA 0)

From `spsgsb/uboot include/amlogic/aml_mmc.h`:

```c
#define EMMC_BOOT_INFO_SIZE 512

struct vpart_property {
    u32 addr;
    u32 size;
};

struct storage_emmc_boot_info {
    u32 version;             // offset 0
    u32 rsv_base_addr;       // offset 4   (in sectors)
    struct vpart_property dtb;   // offset 8  (vendor leaves zero)
    struct vpart_property ddr;   // offset 16 (location of ddr-parameter virtual partition)
    u8  reserved[508 - 24];  // offset 24..507
    u32 checksum;            // offset 508
};
```

Values used by `flash_boot_partition.py`:

| Field          | Value (decimal) | Value (hex)  | Meaning |
|---------------|----------------|--------------|---------|
| version        | 1              | 0x00000001   | always 1 |
| rsv_base_addr  | 73728          | 0x12000      | `MMC_RESERVED_OFFSET / 512` = 0x02400000 / 0x200 |
| dtb.addr       | 0              | 0x00000000   | vendor leaves zero |
| dtb.size       | 0              | 0x00000000   | vendor leaves zero |
| ddr.addr       | 16384          | 0x4000       | `DDR_PARAMETER_OFFSET / 512` (relative to reserved) |
| ddr.size       | 4              | 0x00000004   | `DDR_PARAMETER_SIZE / 512` (4 sectors = 0x800 bytes) |
| checksum       | computed       | 0x00016005   | sum of u32s at indices 0..126 |

### Checksum algorithm

From `_calc_boot_info_checksum` in `cmd_aml_mmc.c`:

```c
do {
    checksum += buffer[i];
} while (i++ < ((EMMC_BOOT_INFO_SIZE >> 2) - 2));
```

Which is: sum of all `u32` values at indices 0..126 (offsets 0..504),
omitting the checksum field itself at index 127 (offsets 508..511).

Modular arithmetic (32-bit wrap), little-endian.

### What BL2 actually does with this: nothing

The `rsv_base_addr` + `ddr.addr` fields nominally point BL2 at DDR-init
parameters in the user area's reserved region. They do not: **BL2 never
reads this sector.** Its only job is to occupy LBA 0 so that BL2 itself
begins at LBA 1. The DDR timings that actually run are compiled into BL2
(vendor `firmware/timing.c`).

Verified on hardware 2026-08-12, escalating, on both slots each time:
zeroing `ddr.addr`/`ddr.size` with the checksum recomputed boots; zeroing
all 512 bytes boots; filling all 512 bytes with non-zero garbage, a
nonsense version and a deliberately wrong checksum also boots.

We still write a well-formed info_sector — it is free, and it keeps the
image byte-compatible with vendor tooling that does parse it. But nothing
in the boot path depends on its contents.

On a terraformed unit the pointer is meaningless anyway: rsv_base
`0x12000` + ddr.addr `0x4000` lands at LBA `0x16000`, which is inside
`boot_a` under our GPT layout, so BL2 would have been reading a FAT
filesystem as "DDR timing" on every boot.

## User-area layout (Amlogic MPT-defined)

Vendor partitions in user area, by byte offset:

```
0x00000000    bootloader mirror (LBA 0+, used by BL2 fallback path 2)
0x02400000    AML MPT (Master Partition Table, ~1.5 KiB)
                magic: "MPT\0"
                version: "01.00.00"
                entries: 18 on stock device
0x02c00000    ddr-parameter (8 MiB into reserved; pointed at by info_sector)
0x08400000    fip_a (4 MiB)
0x09000000    fip_b (4 MiB)
0x51e16000    misc (8 MiB, A/B slot priority block)
... (other partitions per superbird_partitions.py)
```

### The emmckey enclave

LBA 73760-74271 (256 KiB block) of the user area is **hardware-guarded**.
`mmc erase` refuses to touch it with:

```
emmckey_is_access_range_legal, keys 73760, keye 74271
Emmckey: Access range is illegal!
```

Raw `mmc write` CAN write to this range but probably shouldn't. It's
inside the AML reserved region and likely holds RPMB or similar keys.
For repartitioning purposes, leave it alone.

## Recovery surface

| eMMC state                  | mask ROM behavior                    | Recovery |
|----------------------------|--------------------------------------|----------|
| Everything intact          | normal boot                          | n/a      |
| User area wiped            | BL2 falls through to boot0/boot1 FIP | normal boot |
| MPT wiped                  | BL2 falls through to bootloader mirror | normal boot |
| boot0 corrupted, boot1 ok  | mask ROM tries boot1                 | normal boot |
| Both boot0 + boot1 wiped   | mask ROM drops to USB Mode (1b8e:c003) | `superbird-tool --burn_mode` |
| BL2 modified illegally     | CHK:21 → USB Mode                    | `superbird-tool --burn_mode` |

The mask ROM USB Mode path is **always** available regardless of eMMC
state. Mask ROM lives on-die and reads buttons + USB before any eMMC
content.
