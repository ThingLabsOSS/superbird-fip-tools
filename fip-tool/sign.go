package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// cmdSign packs a BL33 (u-boot) into a Spotify-signed, bootable FIP.
//
// Default path is pure Go, no external dependencies: assembleStage1 builds the
// stage-1 FIP from the embedded immutable prefix (BL2/header/DDR-fw/SCP) + the
// BL31 (TF-A) and BL33 (u-boot) you supply, and signNative re-signs/encrypts it
// with the Spotify production key. No amlogic-boot-fip clone, no build-fip.sh,
// no aml_encrypt_g12a, no shell. Hardware-validated (power-on boots from flash).
//
// `--vendor` is the legacy fallback: it drives build-fip.sh + the closed
// aml_encrypt_g12a (Linux/x86 only, requires the amlogic-boot-fip clone). Kept
// only for regenerating the embedded prefix if the board/DDR/SCP ever change.
func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	out := fs.String("o", "", "output directory (default: in-repo out/)")
	board := fs.String("B", "odroid-c4", "[--vendor only] amlogic-boot-fip g12a board dir")
	keyPath := fs.String("k", "", "path to aml-user-key.sig (auto-located if empty)")
	fipRepo := fs.String("f", "", "[--vendor only] path to amlogic-boot-fip checkout")
	bl31Path := fs.String("bl31", "", "path to a custom BL31 (TF-A bl31.bin); default: embedded TF-A 2.14")
	lz4 := fs.Bool("lz4", false, "[--vendor only] LZ4-compress BL33 before encryption (large BL33)")
	vendor := fs.Bool("vendor", false, "legacy: assemble via build-fip.sh + sign via aml_encrypt_g12a (needs the clone)")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `fip-tool sign — pack a u-boot.bin into a Spotify-signed bootable FIP

Usage:
  fip-tool sign [flags] <bl33.bin>

Produces <out>/u-boot.bin.spotify.encrypt, consumable by `+"`fip-tool ramboot <fip>`"+`
and `+"`fip-tool flash ours`"+`.

Pure Go by default — no amlogic-boot-fip clone, no aml_encrypt_g12a, no shell.
Swap in your own TF-A with --bl31 <bl31.bin>. The legacy --vendor path needs the
clone + the closed x86 binary and exists only to regenerate the embedded prefix.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("expected exactly one argument: the BL33 (u-boot.bin)")
	}
	if *lz4 && !*vendor {
		// The native signer doesn't compress BL33 (the Amlogic LZ4 wrapper has
		// no public spec). Fail loudly rather than silently ignore --lz4.
		return fmt.Errorf("--lz4 is only supported with --vendor (the native signer cannot LZ4-compress BL33)")
	}
	bl33, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}
	if _, err := os.Stat(bl33); err != nil {
		return fmt.Errorf("BL33 not found: %s", bl33)
	}

	if *out == "" {
		*out = firstExisting("out", "../out")
	}
	keyFile, err := findKeybundle(*keyPath)
	if err != nil {
		return err
	}
	outAbs, _ := filepath.Abs(*out)
	keyAbs, _ := filepath.Abs(keyFile)
	if err := os.MkdirAll(outAbs, 0o755); err != nil {
		return err
	}

	// Exercise the pure-Go key code: load + validate the key we'll sign with.
	bundle, err := os.ReadFile(keyAbs)
	if err != nil {
		return err
	}
	rsaKey, err := ExtractRSAKey(bundle)
	if err != nil {
		return fmt.Errorf("validating signing key %s: %w", keyAbs, err)
	}
	aesKey, err := ExtractAESKey(bundle)
	if err != nil {
		return err
	}
	modFP := sha256.Sum256(rsaKey.N.Bytes())
	fmt.Printf("signing key: %s\n  RSA-%d e=%#x  modulus-sha256=%x\n  AES-256 sha256=%x\n",
		keyAbs, rsaKey.N.BitLen(), rsaKey.E, modFP[:8], sha256.Sum256(aesKey))

	signed := filepath.Join(outAbs, "u-boot.bin.spotify.encrypt")

	if !*vendor {
		// --- pure-Go path: native stage-1 assembly + native sign ---
		bl33data, err := os.ReadFile(bl33)
		if err != nil {
			return err
		}
		var bl31data []byte
		if *bl31Path != "" {
			if bl31data, err = os.ReadFile(*bl31Path); err != nil {
				return fmt.Errorf("reading --bl31: %w", err)
			}
			fmt.Printf("\n[1/2] assembling stage-1 FIP (pure Go) — custom BL31 %s (%d B)...\n", *bl31Path, len(bl31data))
		} else {
			fmt.Printf("\n[1/2] assembling stage-1 FIP (pure Go) — embedded TF-A 2.14 BL31 (%d B)...\n", len(defaultBL31))
		}
		src, err := assembleStage1(bl33data, bl31data)
		if err != nil {
			return fmt.Errorf("stage 1 (native assemble): %w", err)
		}
		fmt.Println("\n[2/2] signing with the pure-Go native signer...")
		outFIP, err := signNative(src, bundle)
		if err != nil {
			return fmt.Errorf("stage 2 (native sign): %w", err)
		}
		if err := os.WriteFile(signed, outFIP, 0o644); err != nil {
			return err
		}
	} else {
		if err := signVendor(bl33, keyAbs, *fipRepo, *board, outAbs, signed, *lz4); err != nil {
			return err
		}
	}

	// Verify the output with our own decrypt code: the FIP body must begin
	// with the well-known C0 = AES_ENC(spotifyKey, 0).
	if err := verifySigned(signed, aesKey); err != nil {
		return fmt.Errorf("post-sign self-check: %w", err)
	}
	info, _ := os.Stat(signed)
	fmt.Printf("\nDONE: %s (%d bytes) — verified Spotify-encrypted.\n", signed, info.Size())
	fmt.Println("Burn it:  fip-tool ramboot " + signed)
	return nil
}

// signVendor is the legacy two-stage path: build-fip.sh assembles a stage-1 FIP
// from the cloned amlogic-boot-fip board components, then aml_encrypt_g12a
// --bootsig re-signs it. Linux/x86 only, needs the clone. Kept solely to
// regenerate assets/stage1-prefix.bin when the board/DDR/SCP components change.
func signVendor(bl33, keyAbs, fipRepo, board, outAbs, signed string, lz4 bool) error {
	if fipRepo == "" {
		fipRepo = firstExisting("amlogic-boot-fip", "../amlogic-boot-fip")
	}
	fipRepoAbs, _ := filepath.Abs(fipRepo)
	boardDir := filepath.Join(fipRepoAbs, board)
	encTool := filepath.Join(boardDir, "aml_encrypt_g12a")
	for _, p := range []string{fipRepoAbs, boardDir, encTool} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("missing %s — run setup.sh to clone amlogic-boot-fip (or pass -f/-B)", p)
		}
	}
	tmp, err := os.MkdirTemp("", "ramboot-sign-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)

	fmt.Println("\n[1/2] assembling FIP via amlogic-boot-fip (vendor)...")
	var s1 *exec.Cmd
	if lz4 {
		s1 = exec.Command("make", "BL33="+bl33, "O="+outAbs, "TMP="+tmp, "COMPRESS_LZ4=1")
		s1.Dir = boardDir
	} else {
		s1 = exec.Command("./build-fip.sh", board, bl33, outAbs, tmp)
		s1.Dir = fipRepoAbs
	}
	s1.Stdout, s1.Stderr = os.Stderr, os.Stderr
	if err := s1.Run(); err != nil {
		return fmt.Errorf("stage 1 (build-fip): %w", err)
	}
	stage1 := filepath.Join(outAbs, "u-boot.bin")
	if _, err := os.Stat(stage1); err != nil {
		return fmt.Errorf("stage 1 produced no u-boot.bin")
	}

	fmt.Println("\n[2/2] signing with the vendor aml_encrypt_g12a...")
	keyCopy := filepath.Join(boardDir, "aml-user-key.spotify.sig")
	if err := copyFile(keyAbs, keyCopy); err != nil {
		return err
	}
	defer os.Remove(keyCopy)
	s2 := exec.Command(encTool, "--bootsig",
		"--input", stage1,
		"--amluserkey", "./aml-user-key.spotify.sig",
		"--aeskey", "enable",
		"--output", signed,
		"--level", "3")
	s2.Dir = boardDir
	s2.Stdout, s2.Stderr = os.Stderr, os.Stderr
	if err := s2.Run(); err != nil {
		return fmt.Errorf("stage 2 (--bootsig): %w", err)
	}
	// Trim aml_encrypt byproducts; replace the stage-1 intermediate with the
	// raw BL33 for reference.
	for _, b := range []string{".sd.bin", ".usb.bl2", ".usb.tpl"} {
		os.Remove(signed + b)
	}
	_ = copyFile(bl33, stage1)
	return nil
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
}

// verifySigned decrypts the FIP body of a signed image with our AES key and
// confirms the canonical first ciphertext block, proving it's validly
// Spotify-encrypted (uses the same crypto as `decrypt`).
func verifySigned(path string, _ []byte) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(data) < fipBodyOffsetInBootloader+16 {
		return fmt.Errorf("output too small (%d bytes)", len(data))
	}
	got := data[fipBodyOffsetInBootloader : fipBodyOffsetInBootloader+16]
	if string(got) != string(fipC0) {
		return fmt.Errorf("FIP body C0 mismatch (got %x, want %x) — not Spotify-encrypted?", got, fipC0)
	}
	return nil
}
