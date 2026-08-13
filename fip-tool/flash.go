package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// Boot-partition image geometry (from flash_boot_partition.py).
const (
	infoSectorSize      = 512
	mmcReservedOffset   = 36 * 1024 * 1024 // 0x02400000
	ddrParameterOffset  = 8 * 1024 * 1024
	ddrParameterSize    = 4 * 512
	// 2 MiB total is a hard ceiling, not a comfortable target: boot
	// partition size varies by fitted eMMC part. Across seven field
	// units, every Samsung S40004 has 4 MiB boot partitions and every
	// Kioxia 004GA0 has exactly 2 MiB, so an image one sector over is
	// fine on half the fleet and rejected on the other half with
	// "MMC: block number 0x1001 exceeds max(0x1000)".
	bootloaderContentSz = 2*1024*1024 - infoSectorSize // 4095 sectors
	totalSectors        = (infoSectorSize + bootloaderContentSz) / 512
	dramStagingAddr     = 0x13000000
)

// makeInfoSector builds the storage_emmc_boot_info struct that goes at LBA 0
// of boot0/boot1 (BL2 reads it post-handoff to find DDR-init params).
func makeInfoSector() []byte {
	buf := make([]byte, infoSectorSize)
	binary.LittleEndian.PutUint32(buf[0:], 1)                     // version
	binary.LittleEndian.PutUint32(buf[4:], mmcReservedOffset/512) // rsv_base_addr
	// dtb.addr/size (offsets 8,12) left zero — vendor convention
	binary.LittleEndian.PutUint32(buf[16:], ddrParameterOffset/512) // ddr.addr
	binary.LittleEndian.PutUint32(buf[20:], ddrParameterSize/512)   // ddr.size
	var sum uint32                                                  // checksum over u32s 0..126
	for i := 0; i < 127; i++ {
		sum += binary.LittleEndian.Uint32(buf[i*4 : i*4+4])
	}
	binary.LittleEndian.PutUint32(buf[127*4:], sum)
	return buf
}

func padContent(b []byte) ([]byte, error) {
	if len(b) > bootloaderContentSz {
		return nil, fmt.Errorf("bootloader content %d exceeds %d bytes (2 MiB layout)", len(b), bootloaderContentSz)
	}
	out := make([]byte, bootloaderContentSz)
	copy(out, b)
	return out, nil
}

// buildImageOurs: info_sector + stock BL2 (first 64 KiB) + our re-signed FIP
// body (signed_fip[0x10000:]), padded to 2 MiB.
func buildImageOurs(stockPath, fipPath string) ([]byte, error) {
	stock, err := os.ReadFile(stockPath)
	if err != nil {
		return nil, fmt.Errorf("reading stock-bootloader: %w", err)
	}
	if len(stock) < 0x10000 {
		return nil, fmt.Errorf("stock-bootloader too small (need >=64 KiB): %s", stockPath)
	}
	fip, err := os.ReadFile(fipPath)
	if err != nil {
		return nil, fmt.Errorf("reading signed-fip: %w", err)
	}
	if len(fip) < 0x10000 {
		return nil, fmt.Errorf("signed-fip too small (need >=64 KiB): %s", fipPath)
	}
	content := append(append([]byte{}, stock[:0x10000]...), fip[0x10000:]...)
	content, err = padContent(content)
	if err != nil {
		return nil, err
	}
	return append(makeInfoSector(), content...), nil
}

// buildImageStock: info_sector + unmodified stock content (recovery flash).
func buildImageStock(stockPath string) ([]byte, error) {
	stock, err := os.ReadFile(stockPath)
	if err != nil {
		return nil, fmt.Errorf("reading stock-bootloader: %w", err)
	}
	if len(stock) > bootloaderContentSz {
		stock = stock[:bootloaderContentSz]
	}
	content, err := padContent(stock)
	if err != nil {
		return nil, err
	}
	return append(makeInfoSector(), content...), nil
}

// buildImageRaw: an already-complete 2 MiB image, used verbatim.
func buildImageRaw(rawPath string) ([]byte, error) {
	img, err := os.ReadFile(rawPath)
	if err != nil {
		return nil, err
	}
	if want := infoSectorSize + bootloaderContentSz; len(img) != want {
		return nil, fmt.Errorf("raw image must be exactly %d bytes, got %d", want, len(img))
	}
	return img, nil
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return paths[len(paths)-1] // fall back to last; error surfaces at open
}

func cmdFlash(args []string) error {
	usage := func() {
		fmt.Fprint(os.Stderr, `fip-tool flash — build (and optionally flash) a boot0/boot1 image

Usage:
  fip-tool flash <ours|stock|raw> [flags]

  ours   stock BL2 (first 64 KiB) + your re-signed FIP body  (the custom-fw path)
  stock  unmodified stock bootloader                          (recovery)
  raw    a pre-built 2 MiB image, verbatim

Flashing writes to boot0+boot1 via vendor burn-mode u-boot (1b8e:c003). Most
of the time you only want --dry-run -o image.bin and then flash via fastboot.

Flags:
`)
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		usage()
		if len(args) == 0 {
			return fmt.Errorf("flash requires a mode: ours|stock|raw")
		}
		return nil
	}
	mode := args[0]

	fs := flag.NewFlagSet("flash", flag.ContinueOnError)
	stockBL := fs.String("stock-bootloader", "", "stock bootloader image (default: in-repo stock.bootloader.bin)")
	signedFip := fs.String("signed-fip", "", "fip-tool sign output (default: in-repo out/u-boot.bin.spotify.encrypt)")
	rawImage := fs.String("raw-image", "", "pre-built 2 MiB image (required for raw mode)")
	outImg := fs.String("o", "", "also save the built image to this path")
	boot0only := fs.Bool("boot0-only", false, "only flash boot0 (hwpart 1)")
	boot1only := fs.Bool("boot1-only", false, "only flash boot1 (hwpart 2)")
	dryRun := fs.Bool("dry-run", false, "build the image but do not write to device")
	fs.Usage = usage
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	if *stockBL == "" {
		*stockBL = firstExisting("stock.bootloader.bin", "../stock.bootloader.bin")
	}
	if *signedFip == "" {
		*signedFip = firstExisting("out/u-boot.bin.spotify.encrypt", "../out/u-boot.bin.spotify.encrypt")
	}

	var img []byte
	var err error
	switch mode {
	case "ours":
		img, err = buildImageOurs(*stockBL, *signedFip)
	case "stock":
		img, err = buildImageStock(*stockBL)
	case "raw":
		if *rawImage == "" {
			return fmt.Errorf("raw mode requires --raw-image PATH")
		}
		img, err = buildImageRaw(*rawImage)
	default:
		usage()
		return fmt.Errorf("mode must be ours|stock|raw, got %q", mode)
	}
	if err != nil {
		return err
	}
	fmt.Printf("built image: %d bytes (%d B info_sector + %d B bootloader content)\n",
		len(img), infoSectorSize, len(img)-infoSectorSize)

	if *outImg != "" {
		if err := os.WriteFile(*outImg, img, 0o644); err != nil {
			return err
		}
		fmt.Printf("saved image to %s\n", *outImg)
	}

	hwparts := []int{1, 2}
	switch {
	case *boot0only:
		hwparts = []int{1}
	case *boot1only:
		hwparts = []int{2}
	}
	return flashImage(img, hwparts, *dryRun)
}

// flashImage uploads the image to DRAM and `mmc write`s it to each hwpart via
// vendor burn-mode u-boot bulkcmds. (Ports flash_boot_partition.py's flash().)
func flashImage(img []byte, hwparts []int, dryRun bool) error {
	if dryRun {
		fmt.Printf("[dry-run] would upload %d bytes to DRAM 0x%08x\n", len(img), dramStagingAddr)
		for _, hwp := range hwparts {
			fmt.Printf("[dry-run] would mmc dev 1 %d ; mmc write 0x%08x 0 0x%04x\n", hwp, dramStagingAddr, totalSectors)
		}
		fmt.Println("[dry-run] would mmc dev 1 0 (restore user-area access)")
		return nil
	}

	fmt.Printf("opening Amlogic burn-mode device %04x:%04x...\n", vidAmlogic, pidAmlogic)
	dev, err := Open(vidAmlogic, pidAmlogic, false)
	if err != nil {
		return err
	}
	defer dev.Close()

	fmt.Printf("uploading %d bytes to DRAM 0x%08x...\n", len(img), dramStagingAddr)
	if err := dev.WriteLargeMemory(dramStagingAddr, img, 64, false); err != nil {
		return fmt.Errorf("uploading image: %w", err)
	}

	bulk := func(cmd string) error {
		fmt.Printf("  bulkcmd: %s\n", cmd)
		reply, err := dev.BulkCmd(cmd)
		if err != nil {
			return err
		}
		if strings.Contains(strings.ToLower(reply), "fail") {
			return fmt.Errorf("bulkcmd failed: %s -> %s", cmd, reply)
		}
		return nil
	}
	labels := map[int]string{1: "boot0", 2: "boot1", 0: "user"}
	for _, hwp := range hwparts {
		fmt.Printf("writing to %s (hwpart %d):\n", labels[hwp], hwp)
		if err := bulk(fmt.Sprintf("mmc dev 1 %d", hwp)); err != nil {
			return err
		}
		if err := bulk(fmt.Sprintf("mmc write 0x%08x 0 0x%04x", dramStagingAddr, totalSectors)); err != nil {
			return err
		}
	}
	fmt.Println("restoring active hwpart to user area:")
	if err := bulk("mmc dev 1 0"); err != nil {
		return err
	}
	time.Sleep(500 * time.Millisecond)
	fmt.Println("DONE — power-cycle or RTS-reset to see effect")
	return nil
}
