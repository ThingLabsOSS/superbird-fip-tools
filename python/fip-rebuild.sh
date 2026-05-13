#!/usr/bin/env bash
# fip-rebuild.sh — pack a custom BL33 (u-boot) into a Spotify Car Thing
# flashable FIP image, signed with the leaked aml-user-key.sig production
# key so that stock BL2 will accept it.
#
# Usage:
#   ./fip-rebuild.sh -b <bl33.bin> [-o <out-dir>] [-B <board>] [-k <key>] [-f <amlogic-boot-fip>] [--lz4]
#
# Inputs:
#   -b BL33   custom u-boot binary (raw aarch64 ELF / bin from mainline u-boot)
#   -o OUT    output directory (default: ./out)
#   -B BOARD  LibreELEC amlogic-boot-fip board dir to source g12a components
#             from (default: odroid-c4). Alternatives: bananapi-m5,
#             radxa-zero, sei510, u200. Must be a g12a-family board.
#   -k KEY    path to aml-user-key.sig (default: ./keys/aml-user-key.sig)
#   -f FIP    path to amlogic-boot-fip checkout (default: ./amlogic-boot-fip).
#             Run ./setup.sh once to clone it.
#   --lz4     LZ4-compress BL33 before encryption (use if BL33 is large)
#
# Outputs in OUT (everything else aml_encrypt_g12a emits is pruned):
#   u-boot.bin                  raw BL33 input, copied verbatim for reference
#   u-boot.bin.spotify.encrypt  full BL2+FIP signed with spotify key — the
#                               only artifact downstream tooling consumes
#                               (`flash_boot_partition.py --signed-fip ...`,
#                               `superbird-tool --burn_mode <...>`).
#
# Note: flashing this to the `bootloader` partition with libreelec BL2 in the
# first 64 KiB will fail mask ROM RSA verification (CHK:21). To boot at
# power-on, take the FIP body from this output and pair it with stock BL2
# using flash_boot_partition.py.

set -euo pipefail

usage() { sed -n '2,20p' "$0" >&2; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"   # repo root (this script now lives in python/)
BOARD="odroid-c4"
OUT="$ROOT/out"
KEY="$ROOT/keys/aml-user-key.sig"
FIP_REPO="$ROOT/amlogic-boot-fip"
BL33=""
LZ4=0

while [ $# -gt 0 ]; do
    case "$1" in
        -b) BL33="$2"; shift 2 ;;
        -o) OUT="$2"; shift 2 ;;
        -B) BOARD="$2"; shift 2 ;;
        -k) KEY="$2"; shift 2 ;;
        -f) FIP_REPO="$2"; shift 2 ;;
        --lz4) LZ4=1; shift ;;
        -h|--help) usage ;;
        *) echo "unknown arg: $1" >&2; usage ;;
    esac
done

[ -z "$BL33" ]      && { echo "error: -b BL33 is required" >&2; usage; }
[ -f "$BL33" ]      || { echo "error: BL33 not found: $BL33" >&2; exit 1; }
[ -f "$KEY" ]       || { echo "error: key not found: $KEY (run ./setup.sh? or pass -k PATH)" >&2; exit 1; }
[ -d "$FIP_REPO" ]  || { echo "error: amlogic-boot-fip not found: $FIP_REPO (run ./setup.sh)" >&2; exit 1; }
[ -d "$FIP_REPO/$BOARD" ] || { echo "error: board dir not found: $FIP_REPO/$BOARD" >&2; exit 1; }
[ -x "$FIP_REPO/$BOARD/aml_encrypt_g12a" ] || {
    echo "error: $FIP_REPO/$BOARD/aml_encrypt_g12a missing or not executable" >&2
    echo "(is this a g12a-family board?)" >&2
    exit 1
}

BL33="$(readlink -f "$BL33")"
KEY="$(readlink -f "$KEY")"
FIP_REPO="$(readlink -f "$FIP_REPO")"
mkdir -p "$OUT"
OUT="$(readlink -f "$OUT")"

cat <<EOF
================================================================
  superbird-fip-tools — FIP rebuild
  board:    $BOARD
  bl33:     $BL33 ($(stat -c%s "$BL33") bytes)
  key:      $KEY (sha256: $(sha256sum "$KEY" | cut -c1-16)...)
  fip-repo: $FIP_REPO
  out:      $OUT
  lz4:      $LZ4
================================================================
EOF

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo
echo "[1/2] building dev-keyed FIP via amlogic-boot-fip..."
(
    cd "$FIP_REPO"
    if [ "$LZ4" -eq 1 ]; then
        cd "$BOARD"
        make BL33="$BL33" O="$OUT" TMP="$TMP" COMPRESS_LZ4=1
    else
        ./build-fip.sh "$BOARD" "$BL33" "$OUT" "$TMP"
    fi
)

[ -f "$OUT/u-boot.bin" ] || { echo "error: stage 1 produced no u-boot.bin" >&2; exit 1; }
echo "  -> $OUT/u-boot.bin ($(stat -c%s "$OUT/u-boot.bin") bytes)"

echo
echo "[2/2] re-signing with spotify production key..."
(
    cd "$FIP_REPO/$BOARD"
    cp -f "$KEY" ./aml-user-key.spotify.sig
    ./aml_encrypt_g12a --bootsig \
        --input  "$OUT/u-boot.bin" \
        --amluserkey ./aml-user-key.spotify.sig \
        --aeskey enable \
        --output "$OUT/u-boot.bin.spotify.encrypt" \
        --level 3
    rm -f ./aml-user-key.spotify.sig
)

[ -f "$OUT/u-boot.bin.spotify.encrypt" ] || { echo "error: stage 2 produced no output" >&2; exit 1; }

# Trim byproducts. aml_encrypt_g12a emits .sd.bin / .usb.bl2 / .usb.tpl
# variants alongside the FIP, and stage 1 leaves a libreelec-keyed
# u-boot.bin in OUT. None of those are consumed by downstream tooling
# (flash_boot_partition.py / superbird-tool --burn_mode both want the
# full .spotify.encrypt). Replace the libreelec intermediate with a copy
# of the raw BL33 input so OUT ends up with exactly two files.
rm -f "$OUT/u-boot.bin.spotify.encrypt.sd.bin" \
      "$OUT/u-boot.bin.spotify.encrypt.usb.bl2" \
      "$OUT/u-boot.bin.spotify.encrypt.usb.tpl"
cp -f "$BL33" "$OUT/u-boot.bin"

echo
echo "================================================================"
echo "  DONE"
echo "================================================================"
ls -la "$OUT/u-boot.bin" "$OUT/u-boot.bin.spotify.encrypt"
cat <<EOF

Next steps:

  # Flash to boot0/boot1 paired with stock BL2 (boots at power-on):
  ./flash_boot_partition.py ours \\
      --signed-fip $OUT/u-boot.bin.spotify.encrypt
      # (--stock-bootloader defaults to the in-repo stock.bootloader.bin)

  # OR: RAM-load via mask-ROM USB → BL2 → custom FIP (dev iteration):
  superbird-tool --burn_mode $OUT/u-boot.bin.spotify.encrypt

ALWAYS test on an inactive A/B slot first. Recovery via mask ROM USB
(buttons 1+4 + reset) always works.
EOF
