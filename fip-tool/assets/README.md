# fip-tool embedded assets

Binary blobs embedded into `fip-tool` (via `go:embed`) so `fip-tool sign` is
fully self-contained — no `amlogic-boot-fip` clone, no `aml_encrypt_g12a`, no
shell. See `../assemble.go`.

| file | what | bytes |
|------|------|-------|
| `stage1-prefix.bin` | the immutable head of a stage-1 FIP, `[0:0x86570]`: an (inert) BL2 slot + the master-header skeleton + the DDR PHY training firmware gap `[0x14000:0x78000]` + slot0/SCP (Amlogic BL30). None of this changes per build. | 550256 |
| `bl31.bin` | default BL31 = ARM TF-A **v2.14.0** raw image (`bl31.bin`). Override at sign time with `sign -bl31 <your-bl31.bin>`. | 28774 |

`signNative` rebuilds + re-signs everything inside `stage1-prefix.bin` with the
Spotify production key, so the prefix is carried, never trusted — its only job
is to supply the immutable DDR firmware + SCP bodies and the header layout.

## Provenance

Captured from a known-good vendor build: `amlogic-boot-fip` board `odroid-c4`
(DDR fw + SCP + `aml_encrypt_g12a`), with `bl31.bin` = our mainline TF-A 2.14.
The DDR firmware and SCP are Amlogic G12A silicon-support blobs, already
publicly redistributed by LibreELEC/amlogic-boot-fip. The BL2 slot is inert in
our flow (`flash`/`ramboot` pair the FIP body with stock mask-ROM BL2).

## Regenerating (only if the board / DDR fw / SCP change)

```bash
# 1. produce a fresh vendor stage-1 (needs the amlogic-boot-fip clone; setup.sh)
cd amlogic-boot-fip && ./build-fip.sh odroid-c4 /path/to/u-boot.bin /tmp/s1 /tmp/s1tmp

# 2. carve the immutable prefix [0:0x86570]
head -c 550256 /tmp/s1/u-boot.bin > fip-tool/assets/stage1-prefix.bin
cp amlogic-boot-fip/odroid-c4/bl31.bin fip-tool/assets/bl31.bin   # if BL31 changed

# 3. verify byte-equivalence (vendor stage-1 vs native assembler)
cd fip-tool && cp /path/to/u-boot.bin /tmp/s1/bl33.bin
FIPTOOL_ORACLE_DIR=/tmp/s1 go test -run TestAssembleVsVendorStage1
```

`sign --vendor` runs the same vendor pipeline end-to-end if you need it.
