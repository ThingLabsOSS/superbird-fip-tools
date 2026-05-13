package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"testing"
)

// TestSlot0RoundTrip builds a BL30 slot0 payload, then independently verifies
// every property that BL2 relies on: the m3 chunked-AES round-trips, the @AML
// header fields are correct, the keymax prefix is verbatim, and the embedded
// RSA signature validates over the exact range the signer hashes. This needs
// only the (public) keybundle — no large oracle blob.
func TestSlot0RoundTrip(t *testing.T) {
	bundle, err := os.ReadFile("../keys/aml-user-key.sig")
	if err != nil {
		t.Skipf("keybundle not available: %v", err)
	}
	key, err := ExtractRSAKey(bundle)
	if err != nil {
		t.Fatalf("extract key: %v", err)
	}
	aesKey, _ := ExtractAESKey(bundle)
	keymax, _ := extractKeymax(bundle)

	// A body that is deliberately not 512-aligned, to exercise v29 padding.
	body := make([]byte, 4000)
	for i := range body {
		body[i] = byte(i * 7)
	}
	nonce := []byte("0123456789abcdef")
	ts := []byte("20260523000000\x00\x00")

	slot0, err := buildSlot0(body, bundle, nonce, ts)
	if err != nil {
		t.Fatalf("buildSlot0: %v", err)
	}

	stage1, err := m3Crypt(slot0, aesKey, false) // decrypt
	if err != nil {
		t.Fatalf("m3 decrypt: %v", err)
	}

	v29 := (len(body) + 511) &^ 511
	if want := bl30KeymaxLen + bl30BodyOff + v29; len(stage1) != want {
		t.Fatalf("stage1 len = %d, want %d", len(stage1), want)
	}

	// keymax verbatim except the 16-byte nonce.
	if !bytes.Equal(stage1[16:bl30KeymaxLen], keymax[16:]) {
		t.Error("keymax body not preserved verbatim")
	}
	if !bytes.Equal(stage1[0:16], nonce) {
		t.Error("nonce not placed at keymax head")
	}

	h := stage1[bl30KeymaxLen : bl30KeymaxLen+bl30HdrLen]
	if binary.LittleEndian.Uint32(h[0:]) != 0x4C4D4140 {
		t.Error("missing @AML magic")
	}
	if got := binary.LittleEndian.Uint32(h[0x38:]); got != uint32(v29) {
		t.Errorf("payload_size = %d, want %d", got, v29)
	}
	if got := binary.LittleEndian.Uint32(h[0x34:]); got != bl30BodyOff {
		t.Errorf("payload_offset = %d, want %d", got, bl30BodyOff)
	}

	// Verify the embedded signature over hdr[0:64] || v43[320:].
	v43 := stage1[bl30KeymaxLen:]
	sigBytes := v43[bl30HdrLen : bl30HdrLen+bl30SigLen]
	hsh := sha256.New()
	hsh.Write(v43[0:bl30HdrLen])
	hsh.Write(v43[bl30HdrLen+bl30SigLen:])
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hsh.Sum(nil), sigBytes); err != nil {
		t.Errorf("slot0 signature does not verify: %v", err)
	}

	// Body must be present at its declared offset.
	got := v43[bl30BodyOff : bl30BodyOff+len(body)]
	if !bytes.Equal(got, body) {
		t.Error("body not at declared offset")
	}
}
