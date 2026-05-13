package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

// TestBuildBLPrefix checks buildBLPrefix reproduces a real per-BL header+sig
// region (slot3/BL33, decrypted from an aml_encrypt output) byte-for-byte —
// including the deterministic RSA-PKCS#1 v1.5 signature. testdata/blsig_ref.bin
// is the 656-B region; the fields are read back out of it to drive the rebuild.
func TestBuildBLPrefix(t *testing.T) {
	ref, err := os.ReadFile("testdata/blsig_ref.bin")
	if err != nil || len(ref) != blPrefixLen {
		t.Fatalf("read ref: len=%d err=%v", len(ref), err)
	}
	bundle, err := os.ReadFile("../keys/aml-user-key.sig")
	if err != nil {
		t.Skipf("keybundle not available: %v", err)
	}
	key, err := ExtractRSAKey(bundle)
	if err != nil {
		t.Fatalf("extract key: %v", err)
	}

	// fields live in the 384-B signed header at ref[16:400]
	bodySize := int(binary.LittleEndian.Uint64(ref[16+0x10:]))
	bodySHA := ref[16+0x20 : 16+0x40]
	uuid := ref[16+0x40 : 16+0x50]
	aesKey := ref[16+0x50 : 16+0x70]

	got, err := buildBLPrefix(bodySize, bodySHA, uuid, aesKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, ref) {
		for i := 0; i < blPrefixLen; i += 16 {
			if !bytes.Equal(got[i:i+16], ref[i:i+16]) {
				t.Fatalf("BL prefix mismatch @0x%x:\n got  %x\n want %x", i, got[i:i+16], ref[i:i+16])
			}
		}
		t.Fatal("BL prefix length mismatch")
	}
}
