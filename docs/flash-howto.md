# Flash how-to — start-to-finish walkthrough

## Prerequisites

- Linux machine
- Spotify Car Thing with USB cable
- Optional but VERY useful: UART access (3.3V serial on the test pads).
  Not required, but you can't see what mask ROM / BL2 / your u-boot
  prints without it. Most users don't have UART; this guide notes when
  UART helps but doesn't require it.
- Python 3 + pyamlboot:
  ```bash
  sudo apt install python3 python3-pip gcc-aarch64-linux-gnu \
                   binutils-aarch64-linux-gnu build-essential git
  sudo python3 -m pip install git+https://github.com/superna9999/pyamlboot
  ```
- `superbird-tool` available somewhere
  (<https://github.com/thinglabsoss/superbird-tool>). The flash script
  here uses pyamlboot directly and doesn't depend on superbird-tool's
  Python library, but you'll use superbird-tool's `--burn_mode` and
  optionally `--dump_partition`.

## Step 0 — clone and set up

```bash
git clone https://github.com/ThingLabsOSS/superbird-fip-tools.git
cd superbird-fip-tools
./setup.sh          # clones amlogic-boot-fip, checks deps, verifies key
```

`./setup.sh` is idempotent — safe to re-run after fixing missing deps.

## Step 1 — get a copy of the stock bootloader

The hybrid flash needs the stock bootloader (its first 64 KiB is the BL2
mask ROM expects). **This repo already ships it as `stock.bootloader.bin`**
— it's common stock firmware, identical across units, and it's the
default `--stock-bootloader`, so for the normal path you can skip this
step entirely.

If you'd rather use your own unit's image, dump the whole thing once
from a stock device:

```bash
# Get device into USB Burn Mode: hold preset 1+4, reset, then:
cd /path/to/superbird-tool
sudo ./superbird_tool.py --burn_mode
sudo ./superbird_tool.py --dump_partition bootloader bootloader.dump
ls -la bootloader.dump   # should be 4194304 bytes (4 MiB)
```

Then pass it explicitly with `--stock-bootloader bootloader.dump`.
**This dump only needs to happen once per device.** Keep it around as
your golden recovery file.

## Step 2 — build your u-boot

Standard mainline u-boot build for the Car Thing:

```bash
cd /path/to/your/u-boot/checkout
make spotify_carthing_defconfig   # or another G12A defconfig
make -j$(nproc) CROSS_COMPILE=aarch64-linux-gnu-
ls -la u-boot.bin                 # output you'll feed to `fip-tool sign`
```

If you're starting from scratch, see
<https://github.com/elle/superbird-uboot> for a working mainline u-boot
fork with Car Thing support already added.

## Step 3 — wrap u-boot.bin in a signed FIP

Pure Go — no `amlogic-boot-fip` clone, no `aml_encrypt_g12a`, no shell:

```bash
cd superbird-fip-tools
fip-tool/fip-tool sign /path/to/u-boot.bin
ls -la out/
#   custom TF-A:  fip-tool/fip-tool sign -bl31 your/bl31.bin /path/to/u-boot.bin
```

Expected output in `out/`:

- `u-boot.bin.spotify.encrypt` — the full BL2+FIP image, signed with the
  spotify production key. This is what downstream tooling consumes.
  (If you could replace BL2 you'd flash this whole image; you can't —
  see `secure-boot.md`. `fip-tool flash` handles the hybrid.)

The next step uses `u-boot.bin.spotify.encrypt`; the flash step takes its
first 64 KiB (the inert BL2 slot) and discards it, replacing with stock BL2.

> Legacy: `python/fip-rebuild.sh -b /path/to/u-boot.bin` (wraps the vendor
> `aml_encrypt_g12a`, Linux/x86) produces the same file. Superseded by
> `fip-tool sign`.

## Step 4 — get device into USB Burn Mode

If not already there:
```bash
# Hold preset buttons 1+4, press reset (or power-cycle while holding)
sudo /path/to/superbird-tool/superbird_tool.py --burn_mode
sudo /path/to/superbird-tool/superbird_tool.py --find_device
```

You should see `Found device booted in USB Burn Mode (ready for
commands)`. If you instead see "USB Mode (buttons 1+4 held at boot)",
re-run `--burn_mode`.

## Step 5 — flash

```bash
sudo python/flash_boot_partition.py ours \
    --signed-fip ./out/u-boot.bin.spotify.encrypt
#   --stock-bootloader defaults to the in-repo stock.bootloader.bin;
#   add it explicitly only to use your own unit's dump.
```

(Pure-Go equivalent: `fip-tool flash ours` builds the identical image; its
device-write path mirrors this one but is not independently hardware-re-tested,
so the Python tool remains the proven flash path here.)

The script:
1. Builds `info_sector` (`storage_emmc_boot_info` struct, 512 B)
2. Reads first 64 KiB of the stock bootloader (stock BL2)
3. Reads `[0x10000:]` of `u-boot.bin.spotify.encrypt` (our FIP body)
4. Concatenates and pads to exactly 2,097,152 bytes / 2 MiB
   (1 info_sector + 4095 sectors of bootloader content = 4096 sectors total)
5. Uploads to device DRAM at 0x13000000
6. Writes 4096 sectors (`0x1000`) to boot0 (hwpart 1) starting at LBA 0
   (one sector more would exceed the 2 MiB hwpart and `mmc write` rejects it)
7. Writes the same to boot1 (hwpart 2) for redundancy
8. Restores active hwpart to user area

## Step 6 — boot your u-boot

```
Release preset buttons 1+4 (otherwise mask ROM forces USB Mode every reset)
Reset or power-cycle the device
```

Expected boot tag on UART (if you have UART):
```
G12A:BL:0253b8:61aa2d;...;EMMC:0;READ:0;CHK:1F;READ:0;0.0;0.0
```

A single `CHK:1F` is normal — mask ROM reads LBA 0 (info_sector),
fails the signature check (because it's not BL2), retries at LBA 1
(your BL2), succeeds. Three `CHK:1F`s in a row would mean trouble.

Your u-boot runs, panel lights up, prompt appears in ~5 seconds.

If you DON'T have UART: a working boot is "panel shows u-boot logo
within 5-10 seconds of power-on, no Spotify branding ever appears."
A failed boot is "panel stays dark indefinitely." If the latter:
mask ROM is now in USB Mode (USB hub will detect `1b8e:c003`),
recover via Step 0 of the recovery procedure below.

## Recovery (when things go sideways)

You can't brick this device permanently. Mask ROM USB Mode is always
accessible.

### Soft recovery: flash stock back

```bash
# Get into burn mode again
sudo /path/to/superbird-tool/superbird_tool.py --burn_mode

# Restore stock boot0/boot1 (uses the in-repo stock.bootloader.bin;
# pass --stock-bootloader to override with your own dump)
sudo ./flash_boot_partition.py stock
```

### Heavy recovery: restore everything

If the user area was wiped and you need vendor partitions back:

```bash
sudo /path/to/superbird-tool/superbird_tool.py --burn_mode
sudo /path/to/superbird-tool/superbird_tool.py \
    --restore_device /path/to/dump/folder
```

(`/path/to/dump/folder/` should contain `bootloader.dump`, `fip_a.dump`,
`fip_b.dump`, `env.dump`, `system_a.ext2`, etc. — see superbird-tool's
README for the full list.)

### Nuclear option: force mask ROM USB

If the device is completely unresponsive:

1. Disconnect USB
2. Hold buttons 1+4 (with masking tape if needed)
3. Connect USB
4. Device enumerates as `1b8e:c003` regardless of eMMC state
5. From there, `--burn_mode` works

This works even with a completely zeroed eMMC. Mask ROM lives on-die.

## Common pitfalls

- **Writing BL2 at LBA 0 instead of LBA 1** — the boot partition
  layout is info_sector at LBA 0, then BL2+FIP from LBA 1. Our image
  already contains the info_sector as its own first sector, so writing
  the whole image at LBA 0 is correct. What breaks is writing a bare
  BL2+FIP blob (no info_sector) at LBA 0: everything lands one sector
  early, mask ROM sees BL2 at the wrong offset and fails with CHK:1F
  three times.

- **Writing 4097 sectors** — the image is 2 MiB, which is **4096**
  sectors (`0x1000`), info_sector included. `0x1001` is one sector
  past the end. That is survivable on units with 4 MiB boot
  partitions and fails outright on units with 2 MiB ones:

      MMC: block number 0x1001 exceeds max(0x1000)

  Boot partition size is not uniform across the fleet — measured over
  seven units, every Samsung S40004 has 4 MiB and every Kioxia 004GA0
  has 2 MiB. So 2 MiB is a hard ceiling for the image, not a
  comfortable target, and a recipe that overruns it only fails for
  half of users. All three flashers (this script, fip-tool, and
  flashthing) derive the sector count from the image length and get
  this right; hand-typed `mmc write` invocations are where it bites.

- **Forgetting the info_sector** — BL2 must live at LBA 1 with a
  512-byte info_sector ahead of it. Write BL2 at LBA 0 and everything
  is one sector out of place.

  The *contents* turn out not to matter at all. The DDR fields
  nominally point BL2 at parameters in the user area's reserved
  region, but our GPT layout has none — the pointer resolves to LBA
  0x16000, inside boot_a — and BL2 has been reading our FAT
  filesystem as "DDR timing" on every boot without caring. Confirmed
  on hardware, escalating: zeroing ddr.addr/ddr.size on both slots
  boots normally, and so does zeroing all 512 bytes on both slots.
  The timings that actually run are compiled into BL2 (vendor
  firmware/timing.c).

  So the sector is a 512-byte spacer as far as our boot path is
  concerned. Write it anyway — it costs nothing and keeps the image
  identical to a stock one — but the thing that actually matters is
  that BL2 begins at LBA 1.

  (An all-zero sector has a self-consistent checksum, so that test
  does not prove BL2 skips validation entirely — only that zeros
  pass. Non-zero garbage at LBA 0 would settle it.)

- **Wiping boot0/boot1 then can't get into burn mode** — mask ROM
  still drops to USB Mode in this case (no valid BL2 found). Hold
  buttons 1+4 and reset; `superbird-tool --burn_mode` works fine
  uploading BL2+FIP via USB.

- **`amlmmc <partition_name>` failing with "Cannot find dev"** — the
  user-area MPT is wiped, so vendor amlmmc can't look up partitions
  by name. Use raw `mmc dev` + `mmc read/write` (or this script's
  approach) instead.
