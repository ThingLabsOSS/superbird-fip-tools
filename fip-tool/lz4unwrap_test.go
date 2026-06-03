package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// buildLZ4C wraps a single pre-encoded LZ4 block in an Amlogic LZ4C container
// (descriptor + one block header), matching aml_encrypt_g12a's framing.
func buildLZ4C(compressed []byte, plain []byte) []byte {
	var b bytes.Buffer
	b.WriteString(lz4cMagic)
	binary.Write(&b, binary.LittleEndian, uint32(lz4cBlockMax))
	binary.Write(&b, binary.LittleEndian, uint32(len(plain)))
	binary.Write(&b, binary.LittleEndian, uint32(len(compressed)))
	h := sha256.Sum256(plain)
	b.Write(h[:])
	for b.Len() < lz4cDescLen { // pad timestamp area
		b.WriteByte(0)
	}
	b.WriteString(lz4cMagic)  // block header
	b.Write(make([]byte, 32)) // 32-byte block signature
	b.Write(compressed)
	return b.Bytes()
}

// TestLZ4BlockDecodeLiterals exercises a literals-only block.
func TestLZ4BlockDecodeLiterals(t *testing.T) {
	plain := []byte("ABCDEFGHIJKLMNOPQRST") // 20 bytes
	// token: litlen nibble 0xF (=15, "read more"), match nibble 0; +1 extra
	// byte (20-15=5); then 20 literals.
	comp := append([]byte{0xF0, 0x05}, plain...)
	out, _, err := lz4BlockDecode(comp, 0, nil, len(plain))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("literals: got %q want %q", out, plain)
	}
}

// TestLZ4BlockDecodeMatch exercises an overlapping (RLE) match.
func TestLZ4BlockDecodeMatch(t *testing.T) {
	plain := []byte("aaaaaaaaaa") // 10 'a'
	// token 0x15: 1 literal, match length nibble 5 (->5+4=9); literal 'a';
	// offset 1 (LE) -> copies 9 more 'a' from one byte back.
	comp := []byte{0x15, 'a', 0x01, 0x00}
	out, _, err := lz4BlockDecode(comp, 0, nil, len(plain))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("match: got %q want %q", out, plain)
	}
}

// TestDecompressLZ4C round-trips a full container and checks SHA-256
// verification (both success and tamper-detection).
func TestDecompressLZ4C(t *testing.T) {
	plain := []byte("aaaaaaaaaa")
	comp := []byte{0x15, 'a', 0x01, 0x00}
	cont := buildLZ4C(comp, plain)

	if got := findLZ4CDescriptor(cont); got != 0 {
		t.Fatalf("findLZ4CDescriptor = %d, want 0", got)
	}
	out, info, err := extractBL33(cont)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("got %q want %q", out, plain)
	}
	if info.Ucomp != len(plain) || info.Comp != len(comp) {
		t.Fatalf("info = %+v", info)
	}

	// Corrupt the embedded SHA-256 → must fail.
	bad := append([]byte(nil), cont...)
	bad[0x10] ^= 0xff
	if _, _, err := extractBL33(bad); err == nil {
		t.Fatal("expected SHA-256 mismatch error, got nil")
	}
}
