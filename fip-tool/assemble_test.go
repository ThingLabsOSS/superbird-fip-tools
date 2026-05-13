package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// TestAssembleVsVendorStage1 proves the pure-Go stage-1 assembler produces a
// FIP that signNative turns into the *exact same bytes* as the vendor
// build-fip.sh stage-1 would. Gated on FIPTOOL_ORACLE_DIR containing:
//   - u-boot.bin : the vendor build-fip.sh stage-1 (its BL33 == the bl33 below)
//   - bl33.bin   : the raw u-boot used to build that stage-1
//
// The embedded default BL31 must match the one the oracle stage-1 was built with.
func TestAssembleVsVendorStage1(t *testing.T) {
	dir := os.Getenv("FIPTOOL_ORACLE_DIR")
	if dir == "" {
		t.Skip("set FIPTOOL_ORACLE_DIR to a {u-boot.bin, bl33.bin} oracle pair")
	}
	realStage1, err := os.ReadFile(filepath.Join(dir, "u-boot.bin"))
	if err != nil {
		t.Fatalf("read vendor stage-1: %v", err)
	}
	bl33, err := os.ReadFile(filepath.Join(dir, "bl33.bin"))
	if err != nil {
		t.Skipf("bl33.bin not in oracle dir: %v", err)
	}
	bundle, err := os.ReadFile("../keys/aml-user-key.sig")
	if err != nil {
		t.Skipf("keybundle not available: %v", err)
	}

	src, err := assembleStage1(bl33, nil) // nil => embedded default BL31
	if err != nil {
		t.Fatalf("assembleStage1: %v", err)
	}
	got, err := signNative(src, bundle)
	if err != nil {
		t.Fatalf("signNative(assembled): %v", err)
	}
	want, err := signNative(realStage1, bundle)
	if err != nil {
		t.Fatalf("signNative(vendor stage-1): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("native-assembled FIP differs from vendor-stage-1 FIP (len got=%d want=%d)", len(got), len(want))
	}
}

// TestAssembleSelfContained needs no external files: it assembles + signs a FIP
// from the embedded prefix/BL31 and a synthetic BL33, then verifies every
// signature and that the BL33 body round-trips. This is the permanent
// regression guard for the pure-Go sign path.
func TestAssembleSelfContained(t *testing.T) {
	bundle, err := os.ReadFile("../keys/aml-user-key.sig")
	if err != nil {
		t.Skipf("keybundle not available: %v", err)
	}
	key, _ := ExtractRSAKey(bundle)
	aesKey, _ := ExtractAESKey(bundle)

	// deterministic synthetic u-boot, length not 512-aligned to exercise padding
	bl33 := make([]byte, 200000+13)
	rng := rand.New(rand.NewSource(1))
	rng.Read(bl33)

	src, err := assembleStage1(bl33, nil)
	if err != nil {
		t.Fatalf("assembleStage1: %v", err)
	}
	out, err := signNative(src, bundle)
	if err != nil {
		t.Fatalf("signNative: %v", err)
	}

	dec := func(ct []byte) []byte {
		b, _ := aes.NewCipher(aesKey)
		n := len(ct) / 16 * 16
		o := make([]byte, n)
		cipher.NewCBCDecrypter(b, make([]byte, 16)).CryptBlocks(o, ct[:n])
		return o
	}
	ent := func(h []byte, j int) (uint64, uint64) {
		e := 0x20 + 40*j
		return binary.LittleEndian.Uint64(h[e+0x10:]), binary.LittleEndian.Uint64(h[e+0x18:])
	}

	h := dec(out[fipRegionBase : fipRegionBase+masterHeaderLen])
	sum := sha256.Sum256(h[16:masterSigHashTo])
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], h[masterSigOff:masterHeaderLen]); err != nil {
		t.Errorf("master header signature does not verify: %v", err)
	}

	// BL31 + BL33: decrypt payload, check the @AML header signature over [16:400]
	for _, j := range []int{1, 3} {
		o, sz := ent(h, j)
		pt := dec(out[fipRegionBase+o : fipRegionBase+o+sz])
		hh := sha256.Sum256(pt[16:400])
		if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hh[:], pt[400:656]); err != nil {
			t.Errorf("slot%d header signature does not verify: %v", j, err)
		}
	}

	// BL33 body round-trips back to our (padded) input.
	o, sz := ent(h, 3)
	body := dec(out[fipRegionBase+o : fipRegionBase+o+sz])[blPrefixLen:]
	if !bytes.Equal(body[:len(bl33)], bl33) {
		t.Error("BL33 body does not round-trip to the input u-boot")
	}
	for i := len(bl33); i < len(body); i++ {
		if body[i] != 0 {
			t.Errorf("BL33 pad byte %d nonzero", i)
			break
		}
	}

	// BL30 self-signature verifies (slot0 m3 layer).
	mo, ms := ent(h, 0)
	st1, err := m3Crypt(out[fipRegionBase+mo:fipRegionBase+mo+(ms/16*16)], aesKey, false)
	if err != nil {
		t.Fatalf("m3 decrypt slot0: %v", err)
	}
	v43 := st1[bl30KeymaxLen:]
	hh := sha256.New()
	hh.Write(v43[0:bl30HdrLen])
	hh.Write(v43[bl30HdrLen+bl30SigLen:])
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hh.Sum(nil), v43[bl30HdrLen:bl30HdrLen+bl30SigLen]); err != nil {
		t.Errorf("BL30 signature does not verify: %v", err)
	}
}
