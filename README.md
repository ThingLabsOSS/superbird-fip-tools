# superbird-fip-tools

Tooling to rebuild and flash signed FIP (Firmware Image Package) bundles
for the **Spotify Car Thing** (Amlogic G12A "superbird"), letting you
boot your own u-boot / BL31 / kernel chain at power-on instead of the
vendor firmware.

Built and verified during a long night of reverse engineering 2026-05-13.
The hardware is fully owned. There is no Spotify branding, splash, or
firmware running once this is flashed.

> **The primary toolkit is now [`fip-tool/`](fip-tool/) — a single pure-Go
> binary** (`ramboot` / `decrypt` / `flash` / `sign`). Its `sign` does the
> *whole* job in Go — stage-1 FIP assembly **and** signing — with no
> `aml_encrypt_g12a`, no `amlogic-boot-fip` clone, and no shell; the resulting
> FIP body is byte-identical to the hardware-validated image. The original
> Python/shell scripts that pioneered all this live in [`python/`](python/)
> and still work, but Go is the maintained path.

## What this gives you

- **[`fip-tool/`](fip-tool/)** — the Go toolkit: RAM-boot a FIP via mask-ROM
  (`ramboot`), `decrypt` Spotify-signed FIP/DTB blobs, build + `flash` a
  boot0/boot1 image, and `sign` a u-boot into a bootable FIP (pure-Go by
  default; `--vendor` falls back to `aml_encrypt_g12a`).
- **[`python/`](python/)** — the legacy scripts: `fip-rebuild.sh` (wraps
  `aml_encrypt_g12a`), `flash_boot_partition.py`, and `aml_decrypt.py`
  (decrypts FIP/DTB blobs for analysis). Superseded by `fip-tool` but kept
  for reference / cross-checking.
- Docs explaining the secure-boot status, BL2's fallback chain, eMMC
  layout, and recovery procedures.

## Why this works

Spotify open-sourced their u-boot fork at <https://github.com/spsgsb/uboot>
and committed `board/amlogic/superbird_production/aml-user-key.sig` —
the **production AES + RSA signing keys** for the device. We use those keys
to sign+encrypt any FIP content (reproduced entirely in pure Go by
`fip-tool sign`; originally via the vendor `aml_encrypt_g12a --bootsig`), and
BL2 (whose verification key was baked in at signing time) accepts it as if
Spotify produced it themselves.

We can't replace BL2 itself — mask ROM RSA-verifies it against a fused
public-key hash. But we don't need to. BL2 is happy initializing DDR
and handing off to whatever FIP it accepts as signed.

Empirical proof the leaked key is genuine: re-encrypting the FIP HDR
with this key produces **byte-identical 48-byte ciphertext** to stock
`bootloader.dump`'s FIP HDR. Same key, same IV → same ciphertext on
same plaintext. P(coincidence) = 2⁻³⁸⁴.

See `docs/secure-boot.md` for the full story.

## Quick start

```bash
# 1. One-time setup (clones amlogic-boot-fip, checks deps, verifies key)
./setup.sh

# 2. Build the Go toolkit
cd fip-tool && go build -o fip-tool . && cd ..

# 3. Build your u-boot (or use any mainline u-boot binary)
cd ../superbird-uboot   # for example
make spotify_carthing_defconfig
make -j$(nproc) CROSS_COMPILE=aarch64-linux-gnu-
cd ../superbird-fip-tools

# 4. Wrap u-boot.bin in a signed FIP — pure Go, no vendor binary / clone / shell
fip-tool/fip-tool sign ../superbird-uboot/u-boot.bin
#   (swap in your own TF-A with --bl31 your/bl31.bin)

# 5. Get device into mask-ROM USB mode (buttons 1+4 + reset), then flash:
fip-tool/fip-tool flash ours       # stock BL2 + your signed FIP → boot0/boot1

# 6. Release buttons. Power-cycle. Your u-boot runs at power-on.
```

> The Go `fip-tool sign` needs nothing but the repo itself — no
> `amlogic-boot-fip` clone, no `aml_encrypt_g12a`, no `setup.sh`. `setup.sh`
> is only needed for the legacy `python/` scripts or `sign --vendor`.

## Decrypting stock firmware (`aml_decrypt.py`)

For digging into vendor binaries — comparing firmware versions, hunting
panel-init values, reverse-engineering, etc. — `aml_decrypt.py` unpacks
the same FIP envelope this repo builds.

```bash
# one-time: install the only Python dependency
pip install -r python/requirements.txt   # or: pip install pycryptodome

# decrypt a 4 MiB bootloader.dump (BL2 + FIP body); print sub-section map
python/aml_decrypt.py bootloader.dump -o /tmp/fip.bin --map-sections

# decrypt a standalone fip_a / fip_b partition
python/aml_decrypt.py --fip fip_a.dump -o /tmp/fip.bin

# decrypt a DTB partition + locate FDT blobs inside
python/aml_decrypt.py --dtb dtb_partition.bin -o /tmp/dtbs.bin --scan-fdts

# raw AES-256-CBC zero-IV decrypt of any blob signed with this key
python/aml_decrypt.py --raw blob.enc -o blob.bin

# print just the AES key (extracted from the bundle)
python/aml_decrypt.py --show-key dummy -o /dev/null
```

**Extracting the plaintext BL33 (u-boot):** BL33 is LZ4-compressed
*before* AES, in Amlogic's `LZ4C` container (the wrapper
`aml_encrypt_g12a --compress lz4` emits and BL31 inflates at runtime).
That container is just LZ4 block format behind a small custom header, so
it unpacks statically — no live-device RAM-dump needed. Use the Go tool:

```bash
# pull the decompressed vendor u-boot straight out of a bootloader.dump
fip-tool/fip-tool decrypt -bootloader -bl33 -o u-boot.bin bootloader.dump
# …or out of a standalone fip_a / fip_b partition
fip-tool/fip-tool decrypt -fip -bl33 -o u-boot.bin fip_a.dump
```

It verifies the SHA-256 the container embeds over the plaintext (and
falls back to an exact compressed-byte-count check on the OTA builds
that leave that digest field zero). `aml_decrypt.py` stops at the
compressed FIP body; everything else (FIP HDR, BL30, BL31, signing
tables) comes out of either tool.

**Provenance**: this just uses the public key Spotify open-sourced via
`spsgsb/uboot:board/amlogic/superbird_production/aml-user-key.sig`. The
key extraction logic, AES mode (CBC), and IV (zero) were verified by
brute-forcing every 16/32-byte window in the keybundle against a known
plaintext-ciphertext pair from real device data. See the docstring at
the top of `aml_decrypt.py` for full forensic trail.

## What you need that this repo doesn't ship

- **A working build of u-boot** (or another BL33 of your choice).
- A stock bootloader image — **shipped here as `stock.bootloader.bin`**
  (full 4 MiB: info region + BL2 + vendor FIP). It's common stock
  firmware, identical across units, so you don't need to dump your own.
  It's the default `--stock-bootloader` for both the `ours` and `stock`
  builds, and the input `aml_decrypt.py` expects. (If you'd rather use
  your own unit's image: `superbird-tool --dump_partition bootloader
  bootloader.dump`, then pass it via `--stock-bootloader`.)
- **[`superbird-tool`](https://github.com/ThingLabsOSS/superbird-tool)**
  for getting the device into USB Burn Mode and for general device
  manipulation. The flash script here uses `pyamlboot` directly so it
  doesn't depend on superbird-tool's library, but you still need
  superbird-tool to enter burn mode.
- **pyamlboot** (`sudo pip install git+https://github.com/superna9999/pyamlboot`).

## Repo layout

```
.
├── README.md
├── LICENSE
├── setup.sh                    one-shot dependency setup
├── fip-tool/                   Go toolkit: ramboot / decrypt / flash / sign — THE MAIN TOOL
├── python/                     legacy Python/shell tools (superseded by fip-tool)
│   ├── fip-rebuild.sh          wraps aml_encrypt_g12a → signed FIP
│   ├── flash_boot_partition.py builds info_sector + hybrid + flashes
│   ├── aml_decrypt.py          decrypt FIP bodies / DTB partitions for analysis
│   └── requirements.txt        pycryptodome (the only Python dep)
├── stock.bootloader.bin        stock boot partition (info + BL2 + vendor FIP), 4 MiB
├── keys/
│   ├── aml-user-key.sig        spotify production key (from spsgsb/uboot)
│   └── NOTICE.md               provenance, ethics, proof
├── docs/
│   ├── boot-chain.md           mask ROM → BL2 fallback chain explainer
│   ├── emmc-layout.md          physical layout, info_sector struct
│   ├── flash-howto.md          detailed operator walkthrough
│   └── secure-boot.md          high-level "what's mutable" reference
└── (after ./setup.sh)
    └── amlogic-boot-fip/       cloned LibreELEC repo with build-fip.sh
```

## fip-tool — Go toolkit (subproject)

`fip-tool/` is a cross-platform, pure-Go reimplementation of the
device-side tooling — one binary, four subcommands (the only C is cgo→libusb
for raw USB; no external binaries/scripts at all):

| command | replaces |
|---------|----------|
| `fip-tool ramboot <fip>` (RAM-load via mask-ROM) | `superbird-tool --burn_mode` |
| `fip-tool decrypt` | `aml_decrypt.py` |
| `fip-tool flash` | `flash_boot_partition.py` |
| `fip-tool sign` | `fip-rebuild.sh` |

All four are pure Go — libusb + stdlib crypto, no pyamlboot/pycryptodome,
no `aml_encrypt_g12a`, no `amlogic-boot-fip` clone, no shell. The AES + RSA
production keys are extracted from `aml-user-key.sig` in pure Go. ramboot is
hardware-verified; decrypt/flash are byte-identical to the Python tools; `sign`
assembles the stage-1 FIP natively (embedded immutable prefix + your BL31/BL33)
and re-signs it natively, producing a FIP whose bootable body is byte-identical
to the hardware-validated image. The Python tools are fully superseded.

```bash
cd fip-tool && go build -o fip-tool .
# device in mask-ROM USB mode (hold buttons 1+4, reset), then:
./fip-tool ramboot ../out/u-boot.bin.spotify.encrypt
```

See [`fip-tool/README.md`](fip-tool/README.md) for all subcommands, build
deps (libusb), and the native-`sign` analysis.

## Recovery — you can't brick this

The mask ROM USB Mode path is always available, regardless of eMMC
state. Even with the **entire user area zeroed** and corrupted
boot0/boot1 hardware partitions:

1. Hold buttons 1+4 and reset
2. Device enumerates as `1b8e:c003 GX-CHIP`
3. `superbird-tool --burn_mode` uploads vendor BL2 + bootloader.img via
   USB and lands you in vendor burn-mode u-boot
4. Restore boot0/boot1 with `python/flash_boot_partition.py stock` or rebuild
   from scratch

Empirically verified by wiping the eMMC user area down to zeros and
re-flashing everything from USB.

## Status

| Stage                              | Status               |
|-----------------------------------|----------------------|
| FIP body replacement (BL33)        | ✅ Verified working   |
| Boot at power-on from re-signed FIP | ✅ Verified working   |
| Full user-area wipe + recovery      | ✅ Verified working   |
| FIP body decryption (stock analysis)| ✅ Verified working   |
| Replacing BL2                       | ❌ Not possible (fuse-locked) |
| Replacing BL31 with TF-A           | ✅ Verified working (mainline 2.14) |
| Mainline kernel chainload          | ⏳ Future work        |
| GPT user-area partitioning          | ⏳ Future work        |

## Why this matters

The Car Thing was discontinued by Spotify in 2024 with an announcement
that they'd brick devices server-side. Public outcry pulled them back,
but the device remains an orphan. With this tooling, owners can run
their own software stack on hardware they bought outright.

The leaked key was already public — this just makes using it ergonomic.

## Related projects

- [superbird-tool](https://github.com/ThingLabsOSS/superbird-tool) —
  general device-manipulation tool, `--burn_mode`, partition
  dump/restore, chainload via USB.
- [LibreELEC/amlogic-boot-fip](https://github.com/LibreELEC/amlogic-boot-fip) —
  upstream of `aml_encrypt_g12a` and per-board BL30/BL31 components.
- [spsgsb/uboot](https://github.com/spsgsb/uboot) — Spotify's vendor
  u-boot fork. Where the key came from.

## License

MIT. See `LICENSE`. `keys/aml-user-key.sig` is reproduced from
spsgsb/uboot and is not authored by this project — see
`keys/NOTICE.md`.
