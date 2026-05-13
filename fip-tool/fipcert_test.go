package main

import (
	"bytes"
	"os"
	"testing"
)

// TestBuildKeyCert checks buildKeyCert reproduces a real @KEY block (extracted
// from a genuine aml_encrypt_g12a --bootsig output, decrypted) byte-for-byte.
// testdata/keycert_ref.bin is the 1124-byte block; its modulus is at [88:344]
// (little-endian) and timestamp at [0x20:0x30].
func TestBuildKeyCert(t *testing.T) {
	want, err := os.ReadFile("testdata/keycert_ref.bin")
	if err != nil {
		t.Fatalf("read ref: %v", err)
	}
	if len(want) != 1124 {
		t.Fatalf("ref block is %d bytes, want 1124", len(want))
	}
	n := leToBig(want[88 : 88+256]) // modulus, little-endian
	ts := want[0x20:0x30]

	got := buildKeyCert(n, 0x1374b, ts)
	if !bytes.Equal(got, want) {
		for i := 0; i < len(want); i += 16 {
			if !bytes.Equal(got[i:i+16], want[i:i+16]) {
				t.Fatalf("@KEY mismatch @0x%x:\n got  %x\n want %x", i, got[i:i+16], want[i:i+16])
			}
		}
		t.Fatal("@KEY length mismatch")
	}
}
