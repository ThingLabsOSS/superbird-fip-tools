package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// TestSignNativeVsOracle drives the full pure-Go signer against a real
// aml_encrypt_g12a --bootsig pair and checks it reproduces the vendor output.
// Set FIPTOOL_ORACLE_DIR to a directory containing:
//   - u-boot.bin : the stage-1 FIP (build-fip.sh output, the --bootsig input)
//   - signed     : the vendor's --bootsig output of that same u-boot.bin
//
// The test skips when the env var is unset (e.g. CI), since the oracle isn't
// committed.
func TestSignNativeVsOracle(t *testing.T) {
	dir := os.Getenv("FIPTOOL_ORACLE_DIR")
	if dir == "" {
		t.Skip("set FIPTOOL_ORACLE_DIR to a {u-boot.bin, signed} oracle pair")
	}
	source, err := os.ReadFile(filepath.Join(dir, "u-boot.bin"))
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	oracle, err := os.ReadFile(filepath.Join(dir, "signed"))
	if err != nil {
		t.Fatalf("read oracle: %v", err)
	}
	bundle, err := os.ReadFile("../keys/aml-user-key.sig")
	if err != nil {
		t.Skipf("keybundle not available: %v", err)
	}
	aesKey, _ := ExtractAESKey(bundle)
	key, _ := ExtractRSAKey(bundle)

	out, err := signNative(source, bundle)
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

	// master header signature verifies
	h := dec(out[0x10000:0x14000])
	sum := sha256.Sum256(h[16:16128])
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], h[0x3f00:0x4000]); err != nil {
		t.Errorf("master header signature does not verify: %v", err)
	}

	// DDR-fw gap byte-exact vs vendor
	if !bytes.Equal(out[0x14000:0x78000], oracle[0x14000:0x78000]) {
		t.Error("DDR-fw gap [0x14000:0x78000] differs from vendor")
	}

	// BL31 / BL33 payloads byte-exact vs vendor (same body+key ⇒ same bytes)
	oh := dec(oracle[0x10000:0x14000])
	for _, j := range []int{1, 3} {
		mo, ms := ent(h, j)
		oo, os2 := ent(oh, j)
		if !bytes.Equal(out[0x10000+mo:0x10000+mo+ms], oracle[0x10000+oo:0x10000+oo+os2]) {
			t.Errorf("slot%d payload differs from vendor", j)
		}
	}

	// BL30 (slot0) self-signature verifies
	mo, ms := ent(h, 0)
	st1, err := m3Crypt(out[0x10000+mo:0x10000+mo+(ms/16*16)], aesKey, false)
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
