// fip-tool — a cross-platform, pure-Go toolkit for the Spotify Car Thing.
// One binary replacing the Python/bash device-side tooling in
// superbird-fip-tools:
//
//	fip-tool ramboot <fip>     RAM-load a signed FIP via mask-ROM (--burn_mode)
//	fip-tool decrypt ...       decrypt an Amlogic FIP / DTB blob (aml_decrypt.py)
//	fip-tool flash ...         build/flash a boot-partition image (flash_boot_partition.py)
//	fip-tool sign ...          pack + AES-encrypt + RSA-sign a FIP (fip-rebuild.sh)
//
// They share one libusb (gousb) + crypto core. The AES/RSA keys come from the
// leaked Spotify production bundle aml-user-key.sig (see keybundle.go).
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usageTop()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "ramboot":
		err = cmdRamboot(args)
	case "decrypt":
		err = cmdDecrypt(args)
	case "flash":
		err = cmdFlash(args)
	case "sign":
		err = cmdSign(args)
	case "-h", "--help", "help":
		usageTop()
		return
	default:
		usageTop()
		err = fmt.Errorf("unknown command %q", cmd)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usageTop() {
	fmt.Fprint(os.Stderr, `fip-tool — Car Thing FIP toolkit (pure Go)

Usage:
  fip-tool <command> [flags] [args]

Commands:
  ramboot   RAM-load a signed FIP via mask-ROM USB (hold buttons 1+4, reset)
  decrypt   decrypt an Amlogic FIP body / DTB partition / raw blob
  flash     build (and optionally flash) a boot0/boot1 partition image
  sign      pack, AES-encrypt and RSA-sign a u-boot.bin into a bootable FIP

Run "fip-tool <command> -h" for command-specific flags.
`)
}
