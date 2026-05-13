#!/usr/bin/env bash
# setup.sh — OPTIONAL setup for the legacy paths only.
#
# The primary Go toolkit (fip-tool/) needs NONE of this: `fip-tool sign`
# assembles + signs a FIP entirely in pure Go from an embedded prefix, with no
# amlogic-boot-fip clone, no aml_encrypt_g12a, no shell. Just `go build`.
#
# This script clones LibreELEC's amlogic-boot-fip repo (build-fip.sh +
# aml_encrypt_g12a + board components) and checks Python/cross-compiler deps.
# You only need it for: the legacy python/ scripts, or `fip-tool sign --vendor`
# (which exists solely to regenerate fip-tool/assets/stage1-prefix.bin).
#
# Idempotent: safe to re-run.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

echo "=== superbird-fip-tools setup ==="
echo

# --- amlogic-boot-fip ----------------------------------------------------
if [ -d amlogic-boot-fip/.git ]; then
    echo "[ok] amlogic-boot-fip already cloned"
else
    echo "[fetch] cloning amlogic-boot-fip..."
    git clone --depth=1 https://github.com/LibreELEC/amlogic-boot-fip.git
fi

# --- dependency checks ---------------------------------------------------
echo
echo "=== dependency checks ==="

check() {
    local what="$1" cmd="$2" hint="$3"
    if eval "$cmd" >/dev/null 2>&1; then
        echo "[ok] $what"
    else
        echo "[MISSING] $what — $hint"
        MISSING=1
    fi
}

MISSING=0
check "python3"            "python3 --version"            "install python3"
check "pyamlboot"          "python3 -c 'import pyamlboot'" "sudo python3 -m pip install git+https://github.com/superna9999/pyamlboot"
check "aarch64-gcc"        "aarch64-linux-gnu-gcc --version" "sudo apt install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu"
check "make"               "make --version"               "sudo apt install build-essential"
check "lz4 (optional)"     "lz4 --version"                "sudo apt install lz4 (only needed for --lz4 mode)"

# --- key check ------------------------------------------------------------
echo
if [ -f keys/aml-user-key.sig ]; then
    SHA=$(sha256sum keys/aml-user-key.sig | cut -d' ' -f1)
    EXPECTED=f48c731e064193c6584fe3785c193e6ec0ed51c892b5c20457641945cf906afc
    if [ "$SHA" = "$EXPECTED" ]; then
        echo "[ok] keys/aml-user-key.sig matches expected sha256"
    else
        echo "[warn] keys/aml-user-key.sig sha256 differs from expected:"
        echo "       got:      $SHA"
        echo "       expected: $EXPECTED"
        echo "       (this might be fine if you have a different vintage of the key, but verify against spsgsb/uboot)"
    fi
else
    echo "[fetch] keys/aml-user-key.sig missing — fetching from spsgsb/uboot..."
    mkdir -p keys
    curl -fsSL -o keys/aml-user-key.sig \
        'https://raw.githubusercontent.com/spsgsb/uboot/master/board/amlogic/superbird_production/aml-user-key.sig'
    SHA=$(sha256sum keys/aml-user-key.sig | cut -d' ' -f1)
    echo "[ok] fetched. sha256: $SHA"
fi

# --- final ---------------------------------------------------------------
echo
if [ "$MISSING" -ne 0 ]; then
    echo "Setup is INCOMPLETE — install the missing dependencies above and re-run ./setup.sh."
    exit 1
fi

cat <<EOF

=== ready ===

The Go toolkit (fip-tool/) is the primary path now. Build it and sign:

  cd fip-tool && go build .
  ./fip-tool sign /path/to/your/u-boot.bin     # pure-Go, no vendor binary
  ./fip-tool ramboot ../out/u-boot.bin.spotify.encrypt   # RAM-boot to test

The original Python/shell scripts live in python/ (kept for reference):

  python/fip-rebuild.sh -b /path/to/your/u-boot.bin
  sudo python/flash_boot_partition.py ours --signed-fip ./out/u-boot.bin.spotify.encrypt

(See README.md and fip-tool/README.md for the full walkthrough + recovery.)
EOF
