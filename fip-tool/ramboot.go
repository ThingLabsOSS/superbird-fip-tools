package main

import (
	_ "embed"
	"flag"
	"fmt"
	"os"
	"time"
)

// The stock, mask-ROM-RSA-verified BL2 (64 KiB), identical across units.
// Baked in so `ramboot` is self-contained; override with --bl2.
//
//go:embed superbird.bl2.encrypted.bin
var embeddedBL2 []byte

const (
	vidAmlogic = 0x1b8e
	pidAmlogic = 0xc003
)

// cmdRamboot implements: mask-ROM → stock BL2 → AMLC-stream a signed FIP into
// DRAM. Equivalent to superbird-tool's `--burn_mode <signed-fip>`.
func cmdRamboot(args []string) error {
	fs := flag.NewFlagSet("ramboot", flag.ContinueOnError)
	bl2Path := fs.String("bl2", "", "override the embedded stock BL2 with a file")
	verbose := fs.Bool("v", false, "log each AMLC request as the FIP streams")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `fip-tool ramboot — RAM-load a signed FIP via mask-ROM

Streams a signed FIP (with your u-boot as BL33) into DRAM via the Amlogic
mask-ROM -> BL2 -> AMLC path. First get the device into mask-ROM USB mode:
hold buttons 1+4, then reset.

Usage:
  fip-tool ramboot [flags] <signed-fip>

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("expected exactly one argument: the signed FIP to load")
	}

	bl2 := embeddedBL2
	if *bl2Path != "" {
		b, err := os.ReadFile(*bl2Path)
		if err != nil {
			return fmt.Errorf("reading --bl2 %s: %w", *bl2Path, err)
		}
		bl2 = b
		fmt.Printf("Using BL2 from %s (%d bytes)\n", *bl2Path, len(bl2))
	}
	if len(bl2) == 0 {
		return fmt.Errorf("no BL2 available (embedded blob is empty and no --bl2 given)")
	}

	fip, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("reading FIP %s: %w", fs.Arg(0), err)
	}

	fmt.Printf("Opening Amlogic mask-ROM device %04x:%04x...\n", vidAmlogic, pidAmlogic)
	dev, err := Open(vidAmlogic, pidAmlogic, *verbose)
	if err != nil {
		return err
	}
	defer dev.Close()

	if product, perr := dev.Product(); perr == nil {
		fmt.Printf("Connected: %q\n", product)
		switch product {
		case "M8-CHIP":
			return fmt.Errorf("device is past BL2 (M8-CHIP); the custom-FIP load needs a fresh " +
				"mask-ROM (GX-CHIP). Power-cycle into mask-ROM (hold buttons 1+4, reset) and retry")
		case "GX-CHIP":
			// expected
		default:
			fmt.Printf("warning: unexpected product %q (expected GX-CHIP); continuing\n", product)
		}
	}

	return burn(dev, bl2, fip)
}

// burn ports superbird_device.bl2_boot(): load BL2, run it, then service
// BL2's AMLC pull requests with slices of the FIP until it stops asking.
func burn(dev *Device, bl2, fip []byte) error {
	fmt.Printf("Uploading BL2 (%d bytes) to %#08x...\n", len(bl2), addrBL2)
	if err := dev.WriteLargeMemory(addrBL2, bl2, 4096, true); err != nil {
		return fmt.Errorf("uploading BL2: %w", err)
	}

	fmt.Printf("Running BL2 at %#08x...\n", addrBL2)
	if err := dev.Run(addrBL2); err != nil {
		return fmt.Errorf("running BL2: %w", err)
	}
	time.Sleep(2 * time.Second) // let BL2 come up before it starts asking

	fmt.Printf("Streaming FIP (%d bytes) via AMLC...\n", len(fip))
	// Sentinel that can't match a real (length, offset); BL2 repeats its
	// last request once it's done, which is how we detect the end.
	prevLength, prevOffset := ^uint32(0), ^uint32(0)
	var seq uint8
	for {
		length, offset, err := dev.GetBootAMLC()
		if err != nil {
			return fmt.Errorf("AMLC request (seq %d): %w", seq, err)
		}
		if length == prevLength && offset == prevOffset {
			break // [BL2 END]
		}
		prevLength, prevOffset = length, offset

		if offset > uint32(len(fip)) {
			return fmt.Errorf("BL2 asked for offset %#x beyond FIP size %d — wrong/truncated FIP?",
				offset, len(fip))
		}
		end := min(uint64(offset)+uint64(length), uint64(len(fip)))
		if dev.verbose {
			fmt.Printf("  AMLC seq=%-3d offset=%#08x length=%d\n", seq, offset, length)
		}
		if err := dev.WriteAMLCData(seq, offset, fip[offset:end]); err != nil {
			return fmt.Errorf("AMLC write (seq %d): %w", seq, err)
		}
		seq++
	}

	fmt.Println("[BL2 END] FIP fully streamed — your u-boot is now running in DRAM.")
	fmt.Println("It re-enumerates as its own USB gadget (e.g. 18d1:fada fastboot).")
	return nil
}
