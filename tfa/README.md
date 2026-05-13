# Car Thing TF-A (BL31)

The Car Thing runs **mainline ARM Trusted Firmware** as BL31 instead of the
Spotify vendor BL31. Rather than carry a whole TF-A fork, this folder holds the
**delta**: the carthing patches, a **prebuilt `bl31.bin`**, and how to rebuild
it. `fip-tool sign --bl31 …` consumes the result.

## Provenance

- **Base:** ARM Trusted Firmware **v2.14** (`VERSION_MAJOR.MINOR = 2.14`),
  upstream `https://github.com/ARM-software/arm-trusted-firmware.git`.
  Base commit: **`8bcd40a58d98dce5fcf63acc0482db0ff8fb08ab`**
  (`Merge "feat(mbedtls): enable AESCE…"`, 2026-05-12 integration branch).
- **Carthing patches:** the 3 in `patches/`, applied in order on top of the base.

## The patches (`patches/`)

| # | what |
|---|------|
| `0001` | **carthing-specific eFuse user-area base** — fixes the eFuse user-area offset for our chip so `AML_SM_EFUSE_*` reads land correctly. |
| `0002` | **EL3 SMC to set the POC reboot-reason** (`AML_SM_SET_REBOOT_REASON` `0x82000099`) — RMW the POC nibble in `AO_SEC_GP_CFG0[7:4]`. Came out of the software→maskrom investigation; kept because EL3 *can* write that AO reg (the POC reboot-reason is settable from BL31 if a stock-BL2 fast-path is ever wanted). Not load-bearing for maskrom. |
| `0003` | **enter mask-ROM USB mode on a "maskrom" reboot reason** — `g12a_system_reset()` checks `PREG_STICKY_REG3` for the tagged MASKROM reason (`0x5242a14d`), and if set, one-shot clears it and sends the SCP a SCPI `USB_BOOT` on the low-priority mailbox before the SCPI software reboot. The SoC comes up in mask-ROM USB mode (`1b8e:c003`) instead of booting — no buttons. This is the firmware half of `maskrom` / `fastboot oem maskrom` / `reboot maskrom` (see `superbird-uboot` + `yocto-scratch/reboot-maskrom-kernel-side.md`). |

## Rebuild from source

```bash
git clone https://github.com/ARM-software/arm-trusted-firmware.git tfa
cd tfa
git checkout 8bcd40a58d98dce5fcf63acc0482db0ff8fb08ab
git am /path/to/superbird-fip-tools/tfa/patches/*.patch

make PLAT=g12a DEBUG=0 CROSS_COMPILE=aarch64-linux-gnu- bl31
# -> build/g12a/release/bl31.bin
```

`git am` preserves the original authorship/messages. If you'd rather not have
commits, `git apply patches/*.patch` works too.

## Prebuilt (`prebuilt/bl31.bin`)

Built from the base + all 3 patches, so you don't have to set up a TF-A tree.

- size: 28774 bytes
- sha256: `086fc83bf25efb3af3f1c716d5d36a56a6598f25881c7a59f52c45c52110e6ae`
  (also in `prebuilt/bl31.bin.sha256`)
- banner: `v2.14.0(release):f574a02`

## Use it with fip-tool

`fip-tool`'s embedded default BL31 (`fip-tool/assets/bl31.bin`, `//go:embed`)
**is this build**, so a plain sign already includes the maskrom hook — `--bl31`
is optional and produces identical bytes:

```bash
./fip-tool/fip-tool sign ../superbird-uboot/u-boot.bin                                 # embedded default
./fip-tool/fip-tool sign --bl31 tfa/prebuilt/bl31.bin ../superbird-uboot/u-boot.bin     # explicit, same result
```

### Keeping the embedded default in sync

After rebuilding BL31 from new patches, refresh both the prebuilt and the
embedded asset, then rebuild the tool so the no-flag default stays current:

```bash
cp build/g12a/release/bl31.bin tfa/prebuilt/bl31.bin
sha256sum tfa/prebuilt/bl31.bin > tfa/prebuilt/bl31.bin.sha256
cp tfa/prebuilt/bl31.bin fip-tool/assets/bl31.bin
cd fip-tool && go build -o fip-tool .
```
