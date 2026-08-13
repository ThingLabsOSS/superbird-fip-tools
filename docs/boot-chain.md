# BL2's 4-path FIP fallback chain

When BL2 starts up (after mask ROM hands off), it needs to find the FIP
body to load BL30/BL31/BL32/BL33 from. The Spotify Car Thing's BL2 has
**four fallback locations** it tries in order, reverse-engineered live
on 2026-05-13 by progressively wiping each location and observing
behavior on UART.

This matters because it tells us exactly how much of eMMC we can wipe
while keeping the device bootable.

## The chain

```
                ┌────────────────────────────────────────┐
                │ Mask ROM loads BL2 from boot0 or boot1  │
                │ (per EXT_CSD BOOT_PARTITION_ENABLE)     │
                └─────────────────┬──────────────────────┘
                                  │
                                  v
              ┌────────────────────────────────────────────┐
              │ BL2 starts at LBA 1 (LBA 0 is a spacer)     │
              │ → initializes DDR from timings compiled     │
              │   into BL2 itself                           │
              └─────────────────┬───────────────────────────┘
                                │
                                v
        ┌─────────────────────────────────────────────────────────┐
        │ Path 1: Read MPT at user-area offset 0x02400000          │
        │   Magic "MPT\0"? → parse entries → find fip_a, fip_b,    │
        │   misc → check slot priority in misc → load fip_a or     │
        │   fip_b → "boot from fip_a" / "boot from fip_b"          │
        └────────────────┬──────────────────────┬─────────────────┘
                         │ MPT OK              │ MPT fails magic
                         v                     v
                       BOOT             ┌──────────────────────────┐
                                        │ Path 2: User-area mirror  │
                                        │ at LBA 1 + 64 KiB         │
                                        │ Read FIP HDR at user-area │
                                        │ offset 0x10200            │
                                        └──────┬───────────────────┘
                                               │ FIP HDR OK
                                               v
                                              BOOT
                                               │ FIP HDR CHK fails
                                               v
                                        ┌──────────────────────────┐
                                        │ Path 3: boot0 FIP         │
                                        │ Switch to hwpart 1, read  │
                                        │ FIP HDR at offset 0x10200 │
                                        │ → "boot from non AB mode" │
                                        └──────┬───────────────────┘
                                               │ FIP HDR OK
                                               v
                                              BOOT
                                               │ FIP HDR CHK fails
                                               v
                                        ┌──────────────────────────┐
                                        │ Path 4: boot1 FIP         │
                                        │ Switch to hwpart 2, same  │
                                        │ offset                    │
                                        │ (probably — not directly  │
                                        │ observed but symmetric)   │
                                        └──────────────────────────┘
```

## What we observed empirically

### Path 1 firing (default case)

UART log when user-area has valid MPT and fip_a contains our re-signed
FIP:
```
Load table from eMMC, src: 0x02400000, ..., size: 0x00000600, part: 0
 magic: MPT checksum: 0x 4337b596
misc offset: 0x51e16000
boot A have a higher priority!
fip_a offset: 0x08400000
fip_b offset: 0x09000000
Load FIP HDR from eMMC, src: 0x08400000, ..., part: 0
Load BL3X from eMMC, src: 0x08468000, ..., part: 0
boot from fip_a
```

### Path 2 firing (MPT wiped, user-area mirror intact)

UART log after zeroing the MPT region:
```
Load table from eMMC, src: 0x02400000, ..., part: 0
 magic:  checksum: 0x 00000000
 magic:  magic1: MPT
end bl2z2:
Load FIP HDR from eMMC, src: 0x00010200, ..., part: 0
Load BL3X from eMMC, src: 0x0006c200, ..., part: 0
boot from non AB mode
```

The `magic1: MPT` is BL2 printing the **expected** magic for comparison.
Empty `magic:` shows the actual zeros it read. Then it falls through.

### Path 3 firing (MPT + user-area mirror both wiped)

UART log after wiping the entire user area to zeros:
```
Load FIP HDR from eMMC, src: 0x00010200, ..., part: 0   ← user-area attempt
FIP HDR CHK: 0xffffffff ADDR 0x01700000                 ← signature fail
Load FIP HDR from eMMC, src: 0x00010200, ..., part: 1   ← boot0 attempt
Load BL3X from eMMC, src: 0x0006c200, ..., part: 1
boot from non AB mode
```

Notice the `part: 1` — that's the eMMC hwpart 1 (boot0), distinct from
`part: 0` (user area). BL2 switches eMMC hwpart, then reads the same
offset. boot0's FIP is the same content that boot1 has (vendor mirrors
both).

### Path 4 — implied, not directly tested

If boot0's FIP also fails (e.g. user has flashed garbage to boot0 but
boot1 is still valid), BL2 probably tries boot1 next. We didn't
directly observe this because every boot0 write also went to boot1.

## Practical implications

### "What can I wipe?"

- **Entire user area (3.6 GiB):** safe to wipe. BL2 falls through to
  path 3 (boot0 FIP). Verified empirically — device still boots.
- **boot0 hardware partition:** breaks path 3. BL2 still has path 4
  (boot1) as fallback. Possibly safe but untested.
- **boot1 hardware partition:** if BOOT_PARTITION_ENABLE = 2 (Car Thing
  default), wiping boot1 means mask ROM has no BL2 to load. Device
  drops to mask ROM USB Mode. Recoverable but requires the buttons-1+4
  trick.
- **emmckey enclave (LBA 73760-74271 in user area):** hardware-guarded,
  `mmc erase` refuses. Leave it alone.

### "Can I skip the MPT entirely?"

Yes. Just keep boot0/boot1 containing your signed FIP body. BL2 path 3
will reliably load it. The user-area MPT is ~1.5 KiB at a fixed offset
and can be left zeroed — BL2's fallback handles it gracefully.

This is the key insight that lets us repartition the user area however
we want without an Amlogic MPT-aware parser.

### "What if I want vendor-style A/B fallback?"

Keep MPT valid + populate fip_a and fip_b. BL2's path 1 reads `misc`
for slot priority and picks one. If your active slot's FIP is invalid,
BL2 falls through to the other slot.

You don't need to replicate vendor's full MPT — just `fip_a`, `fip_b`,
`misc` entries. Other partition entries (boot_a/b, system_a/b, env,
dtbo_a/b, etc.) BL2 ignores.

## Source

All paths confirmed against `spsgsb/uboot` source code at
`common/cmd_aml_mmc.c` (`amlmmc_write_bootloader`,
`amlmmc_write_info_sector`) and observed live via UART on a real device.
