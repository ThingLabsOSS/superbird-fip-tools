# TF-A patches for Spotify Car Thing

Mainline ARM Trusted Firmware (TF-A) works on the Spotify Car Thing's
S905D2 with **one** small local patch against `plat/amlogic/g12a` — it
encodes Spotify's eFuse user-area layout and isn't upstreamable as-is.

The Car Thing FIP signer consumes the resulting `bl31.bin` directly —
`fip-tool sign -bl31 <bl31.bin> u-boot.bin` (pure Go, no clone, no vendor
binary). This gives us a fully open BL31, swappable per build.

## Patches

| # | File | Status |
|---|---|---|
| 0001 | `eFuse user-area base 0x140 → 0x1a0` | **works** — `printenv serial#` returns per-unit usid |

### Dropped: 0002 — `AML_SM_SET_REBOOT_REASON` SMC

Removed 2026-05-24. It tried to stash the reboot reason in an AO register
from BL31, but **no AP/EL3 write to the SCP-owned `AO_SEC_SD_CFG15`
(`0xff80023c`) is possible — it hard-hangs the bus** (proven from a live
SMC *and* the reset path; see the `carthing-tfa-swap` memory). The reboot
reason moved entirely to u-boot using a CPU-writable `PREG_STICKY`
register instead — see `superbird-uboot/docs/reboot-bootloader.md`. BL31
is now eFuse-patch-only. The old patch lives in git history if the EL3-AO
angle is ever revisited for the software-maskrom investigation.

## Building

```sh
# 1. Clone TF-A upstream (or use any existing checkout)
git clone --depth 1 https://github.com/ARM-software/arm-trusted-firmware.git ../superbird-tfa
cd ../superbird-tfa

# 2. Apply the patch
git am /path/to/tfa-patches/*.patch

# 3. Build BL31 for g12a (TF-A emits build/g12a/release/bl31.bin)
make CROSS_COMPILE=aarch64-linux-gnu- PLAT=g12a DEBUG=0

# 4. Sign your u-boot with this BL31 + flash — pure Go, no clone/vendor binary
cd /path/to/superbird-fip-tools
./fip-tool/fip-tool sign \
    -bl31 ../superbird-tfa/build/g12a/release/bl31.bin \
    ../superbird-uboot/u-boot.bin
./fip-tool/fip-tool flash ours
```

To make a TF-A build the *default* BL31 (used when `-bl31` is omitted), copy it
over the embedded asset and rebuild fip-tool:
`cp build/g12a/release/bl31.bin fip-tool/assets/bl31.bin && (cd fip-tool && go build -o fip-tool .)`.

After flashing, BL31's boot banner should change from
`v1.3(release):4fc40b1, Built : 15:57:33, May 22 2019` (vendor) to
`v2.14.0(release):*, Built : <today>` (mainline) and the
`ERROR: Error initializing runtime service opteed_fast` line goes
away (TF-A doesn't ship an OP-TEE dispatcher).
