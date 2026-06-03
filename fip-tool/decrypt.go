package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
)

// FIP body lives at this offset inside a 4 MiB bootloader.dump (after BL2).
const fipBodyOffsetInBootloader = 0x10000

// fipC0 is the well-known first ciphertext block of a FIP body: AES_ENC(K, 0).
// The first 16 plaintext bytes of every FIP section are zero (the MAC slot),
// so this constant identifies an encrypted FIP regardless of firmware vintage.
var fipC0, _ = hex.DecodeString("16dcfdb77c39ac15998ddbcf8c4132cc")

// decryptCBC does AES-256-CBC with a zero IV, truncating any trailing partial
// block (FIP/partition padding), matching aml_decrypt.py.
func decryptCBC(ct, key []byte) ([]byte, error) {
	if len(ct)%aes.BlockSize != 0 {
		ct = ct[:len(ct)/aes.BlockSize*aes.BlockSize]
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(pt, ct)
	return pt, nil
}

func detectInputKind(data []byte) string {
	if len(data) >= fipBodyOffsetInBootloader+16 &&
		bytes.Equal(data[fipBodyOffsetInBootloader:fipBodyOffsetInBootloader+16], fipC0) {
		return "bootloader_dump"
	}
	if len(data) >= 16 && bytes.Equal(data[:16], fipC0) {
		return "fip_body"
	}
	return "raw"
}

func cmdDecrypt(args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	out := fs.String("o", "", "output file for plaintext (required unless --show-key)")
	keybundle := fs.String("keybundle", "", "path to aml-user-key.sig (auto-located if empty)")
	showKey := fs.Bool("show-key", false, "print the extracted AES key and exit")
	mFip := fs.Bool("fip", false, "treat input as a standalone FIP body")
	mBoot := fs.Bool("bootloader", false, "treat input as bootloader.dump (BL2 + FIP body)")
	mDtb := fs.Bool("dtb", false, "treat input as a raw DTB partition dump")
	mRaw := fs.Bool("raw", false, "raw AES-256-CBC zero-IV decrypt, no structure parsing")
	mBl33 := fs.Bool("bl33", false, "extract + LZ4-decompress the BL33 (u-boot) to -o (verifies SHA-256)")
	mapSecs := fs.Bool("map-sections", false, "print a map of FIP sub-sections (@AML anchors)")
	scanFdts := fs.Bool("scan-fdts", false, "scan plaintext for FDT blobs")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `fip-tool decrypt — decrypt Amlogic FIP / DTB blobs (Spotify key)

Usage:
  fip-tool decrypt [flags] <input>

Input type is auto-detected; override with --fip/--bootloader/--dtb/--raw.
Use --bl33 to pull the decompressed u-boot (BL33) out instead of the FIP.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	bundle, err := loadKeybundle(*keybundle)
	if err != nil {
		return err
	}
	key, err := ExtractAESKey(bundle)
	if err != nil {
		return err
	}
	if *showKey {
		fmt.Printf("AES-256 key: %s\n", hex.EncodeToString(key))
		return nil
	}

	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("expected exactly one input file")
	}
	if *out == "" {
		return fmt.Errorf("-o output is required")
	}
	ct, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "loaded %d bytes from %s\n", len(ct), fs.Arg(0))

	kind := detectInputKind(ct)
	switch {
	case *mBoot:
		kind = "bootloader_dump"
	case *mFip:
		kind = "fip_body"
	case *mDtb:
		kind = "dtb_partition"
	case *mRaw:
		kind = "raw"
	}
	fmt.Fprintf(os.Stderr, "mode: %s\n", kind)

	src := ct
	if kind == "bootloader_dump" {
		src = ct[fipBodyOffsetInBootloader:]
	}
	pt, err := decryptCBC(src, key)
	if err != nil {
		return err
	}

	if *mBl33 {
		if kind != "bootloader_dump" && kind != "fip_body" {
			return fmt.Errorf("--bl33 requires a bootloader.dump or FIP body input (got %s)", kind)
		}
		ub, info, err := extractBL33(pt)
		if err != nil {
			return err
		}
		if err := os.WriteFile(*out, ub, 0o644); err != nil {
			return err
		}
		integrity := "SHA-256 verified"
		if !info.Verified {
			integrity = "byte-exact decode (digest field absent, unverified)"
		}
		fmt.Fprintf(os.Stderr, "BL33: LZ4-decompressed %d -> %d bytes (built %s), %s\n",
			info.Comp, info.Ucomp, info.Timestamp, integrity)
		if v := ubootVersion(ub); v != "" {
			fmt.Fprintf(os.Stderr, "BL33: %s\n", v)
		}
		fmt.Fprintf(os.Stderr, "wrote %d bytes to %s\n", len(ub), *out)
		return nil
	}

	if err := os.WriteFile(*out, pt, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %d bytes to %s\n", len(pt), *out)

	if *mapSecs && (kind == "bootloader_dump" || kind == "fip_body") {
		fmt.Println("\n=== FIP sub-section map (@AML anchors) ===")
		for _, s := range mapFIPSections(pt) {
			fmt.Printf("  0x%06x  len=0x%06x  %s\n", s.off, s.length, s.label)
		}
	}
	if *scanFdts {
		fmt.Println("\n=== FDT blobs in plaintext ===")
		for _, off := range findFDTBlobs(pt) {
			total := binary.BigEndian.Uint32(pt[off+4 : off+8])
			fmt.Printf("  offset=0x%06x  totalsize=0x%x\n", off, total)
		}
	}
	return nil
}

type fipSection struct {
	off, length int
	label       string
}

// mapFIPSections summarizes a decrypted FIP body by anchoring on the @AML
// magic at 16-byte-aligned offsets (matches aml_decrypt.py's heuristic).
func mapFIPSections(pt []byte) []fipSection {
	var anchors []int
	magic := []byte("@AML")
	for i := 0; i+4 <= len(pt); i += 16 {
		if bytes.Equal(pt[i:i+4], magic) {
			anchors = append(anchors, i)
		}
	}
	label := func(off int) string {
		switch {
		case off == 0x10:
			return "FIP HDR (entry table + sigs)"
		case off >= 0x4000 && off < 0x5c000:
			return "per-entry metadata / DDR fw / sigs"
		case off == 0x5c010:
			return "BL3X TOC"
		case off >= 0x5c000 && off < 0x70000:
			return "BL30 (SCP)"
		case off >= 0x70000 && off < 0x98000:
			return "BL31 (TF-A) / BL32"
		case off >= 0x98000 && off < 0x130000:
			return "BL33 (u-boot, LZ4-compressed)"
		default:
			return "data"
		}
	}
	var out []fipSection
	for i, off := range anchors {
		next := len(pt)
		if i+1 < len(anchors) {
			next = anchors[i+1]
		}
		out = append(out, fipSection{off, next - off, label(off)})
	}
	return out
}

// findFDTBlobs returns offsets of plausible FDT (device-tree) blobs.
func findFDTBlobs(pt []byte) []int {
	var out []int
	magic := []byte{0xd0, 0x0d, 0xfe, 0xed}
	for i := 0; i+24 <= len(pt); i++ {
		if !bytes.Equal(pt[i:i+4], magic) {
			continue
		}
		total := binary.BigEndian.Uint32(pt[i+4 : i+8])
		version := binary.BigEndian.Uint32(pt[i+20 : i+24])
		if total >= 0x100 && total <= 0x80000 && (version == 16 || version == 17) {
			out = append(out, i)
		}
	}
	return out
}
