# Legacy Python/shell tools

These are the original scripts that pioneered the Car Thing FIP work. They
**still work**, but the maintained path is now the pure-Go [`fip-tool`](../fip-tool/)
(one binary: `ramboot` / `decrypt` / `flash` / `sign`). Kept here for reference
and cross-checking.

| script | what it does | Go equivalent |
|--------|--------------|---------------|
| `fip-rebuild.sh` | wrap a `u-boot.bin` into a signed FIP via `aml_encrypt_g12a` | `fip-tool sign` (pure-Go) |
| `flash_boot_partition.py` | build a boot0/boot1 image + flash via vendor burn mode | `fip-tool flash` |
| `aml_decrypt.py` | decrypt Spotify-signed FIP bodies / DTB partitions for analysis | `fip-tool decrypt` |

## Usage

Run them from the repo root (they resolve `keys/`, `amlogic-boot-fip/`,
`stock.bootloader.bin`, and `out/` relative to the repo root, so the working
directory doesn't matter):

```bash
pip install -r python/requirements.txt        # pycryptodome

python/fip-rebuild.sh -b ../superbird-uboot/u-boot.bin
sudo python/flash_boot_partition.py ours --signed-fip ./out/u-boot.bin.spotify.encrypt
python/aml_decrypt.py --bootloader bootloader.dump -o /tmp/fip.bin --map-sections
```

`fip-rebuild.sh` and the vendor `aml_encrypt_g12a` are Linux/x86-only;
`fip-tool sign` (default, pure-Go) is cross-platform and needs no vendor binary.
