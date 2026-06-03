# fip-tool

The pure-Go Car Thing toolkit for superbird-fip-tools — one binary
replacing the Python/bash device-side tooling. Four subcommands:

| command | what it does | replaces |
|---------|--------------|----------|
| `fip-tool ramboot <fip>` | RAM-load a signed FIP via mask-ROM → BL2 → AMLC | `superbird-tool --burn_mode` |
| `fip-tool decrypt` | AES-256-CBC decrypt of a FIP / DTB / raw blob; `-bl33` decompresses vendor u-boot | `aml_decrypt.py` |
| `fip-tool flash` | build (and optionally flash) a boot0/boot1 image | `flash_boot_partition.py` |
| `fip-tool sign` | pack + AES-encrypt + RSA-sign a u-boot into a bootable FIP | `fip-rebuild.sh` |

All four are pure Go (libusb + stdlib crypto, no Python/pyamlboot/pycryptodome,
no `aml_encrypt_g12a`, no `amlogic-boot-fip` clone, no shell). The AES + RSA
production keys are extracted and validated in pure Go from `aml-user-key.sig`
(`keybundle.go`). `sign` assembles the stage-1 FIP natively too — see below.

## Usage

```bash
# ramboot — device in mask-ROM USB mode (hold buttons 1+4, reset), then:
fip-tool ramboot ../out/u-boot.bin.spotify.encrypt   # -v logs the AMLC stream

# decrypt — auto-detects bootloader.dump / fip body / dtb / raw
fip-tool decrypt -o /tmp/fip.bin ../out/u-boot.bin.spotify.encrypt
fip-tool decrypt --show-key                          # print the AES-256 key
fip-tool decrypt -bootloader -map-sections -o /tmp/x bootloader.dump
fip-tool decrypt -bootloader -bl33 -o u-boot.bin bootloader.dump  # decompress vendor BL33

# flash — build a boot-partition image (then flash via fastboot, or device-write)
fip-tool flash ours --dry-run -o /tmp/boot.bin       # stock BL2 + your signed FIP
fip-tool flash stock --dry-run -o /tmp/boot.bin      # stock recovery image

# sign — pack a BL33 into a Spotify-signed FIP (output in ../out/)
fip-tool sign ../../superbird-uboot/u-boot.bin
```

Note: Go's `flag` package wants flags **before** the positional argument
(`fip-tool decrypt -o out in`, not `... in -o out`).

## Status

- **ramboot (burn)**: pure Go, **hardware-verified** (2026-05-23) — a real
  Car Thing streamed a full FIP and came up as our u-boot (`18d1:fada`).
- **decrypt**: pure Go, verified **byte-identical** to `aml_decrypt.py` on
  `bootloader.dump`, signed FIPs, and `--raw`. `-bl33` LZ4-decompresses the
  vendor u-boot and checks it against the SHA-256 the `LZ4C` container
  embeds (byte-exact on the 2021 boot0/1 image and the 2024 fip_a/fip_b
  mirror builds).
- **flash**: pure Go image builder, verified **byte-identical** to
  `flash_boot_partition.py` (`ours`/`stock`). The device-write path uses
  vendor burn-mode bulkcmds (mirrors the Python; not re-tested on hardware).
- **sign**: **fully pure Go by default** — both stages, no external deps.
  Stage 1 (`assemble.go`) builds the stage-1 FIP from an embedded immutable
  prefix + your BL31/BL33; stage 2 (`signNative`) re-signs it. **Hardware-
  validated** (2026-05-23): the FIP body is byte-identical to the image that
  power-on-boots from flashed boot0/boot1, with the vendor path retired from
  the default flow. Pass `--vendor` to drive `build-fip.sh` + the closed
  `aml_encrypt_g12a` (Linux/x86) instead — only needed to regenerate the
  embedded prefix.

### How the native stage-1 assembler works (`assemble.go`)

`fip-tool sign` no longer shells out to `build-fip.sh` / `aml_encrypt_g12a`.
The genuinely-immutable parts of a stage-1 FIP — the master-header skeleton,
the DDR PHY training firmware, and the Amlogic SCP (BL30) — are fixed silicon
support that never change per build, so they're captured once (from a known-
good vendor build) into `assets/stage1-prefix.bin` (`[0:0x86570]`, embedded via
`go:embed`). At sign time the assembler:

- carries that prefix verbatim (the leading BL2 slot is inert — our flow pairs
  the FIP body with stock mask-ROM BL2),
- appends the **BL31** (TF-A `bl31.bin`, embedded default = 2.14, override with
  `--bl31`) and **BL33** (your `u-boot.bin`) bodies, each zero-padded so the
  payload is 512-aligned,
- patches the master-header payload entries, and hands the result to
  `signNative`.

`TestAssembleVsVendorStage1` proves the output is **byte-identical** to feeding
a real `build-fip.sh` stage-1 through `signNative`; `TestAssembleSelfContained`
re-verifies every signature with no external files.

### How the native signer reproduces `--bootsig`

Verified structure-by-structure against a real `aml_encrypt_g12a` output:

- **master header** (`masterheader.go`): source header + patched payload
  entries / per-slot params / `has_sig`+AESkey / `@KEY` data (BL31+BL33) /
  master RSA sig, then AES-CBC (zero IV). Byte-exact incl. the signature.
- **DDR-fw gap**: carried from the source FIP, then the `@DFM` regions get the
  per-block AES second pass. Byte-exact.
- **BL31 / BL33**: per-BL `@AML` sign (`signBL`) + whole-payload AES. Byte-exact.
- **BL30 / slot0** (`slot0.go`): keymax-prefixed `@AML`+sig+`@KEY`, then the g12
  `m3` chunked AES (2048-B blocks, fresh zero IV each). Carries the full SCP
  with its own 512-aligned padding (BL2 loads per the size field).
- all AES is zero-IV CBC with `aml-user-key.sig[6944:6976]`; all RSA is
  PKCS#1 v1.5 / SHA-256 with the §15 key. The `FIPTOOL_ORACLE_DIR` test checks
  the whole pipeline against a vendor oracle pair.

## Building

Needs Go (1.21+) and a C toolchain — USB goes through
[gousb](https://github.com/google/gousb) → **libusb-1.0** (cgo), the only
practical raw-USB route on all three OSes.

```bash
go build -o fip-tool .
```

Per-platform libusb: Linux `apt install libusb-1.0-0-dev`; macOS
`brew install libusb`; Windows install libusb + bind the device to WinUSB
via [Zadig](https://zadig.akeo.ie/) (same as superbird-tool).

### USB-less build (`CGO_ENABLED=0`)

Only `ramboot` and live `flash` touch USB; `sign`, `flash --dry-run`, and
`decrypt` are pure stdlib. Building with cgo off drops gousb/libusb entirely —
a small static binary with zero external modules, ideal for a build pipeline
(e.g. signing u-boot in a Yocto recipe):

```bash
CGO_ENABLED=0 go build -o fip-tool .
```

The USB commands still exist but fail with a clear "built without USB support"
error. Rebuild with cgo for `ramboot` / flash-to-device.

## Permissions

Raw USB needs privileges: run as root or add a udev rule for `1b8e:c003`,
just like superbird-tool.
