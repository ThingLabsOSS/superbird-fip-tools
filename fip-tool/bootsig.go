package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Native reproduction of aml_encrypt_g12a --bootsig (the spotify-key re-sign).
// Everything is AES-256-CBC with a zero IV (key = amluserkey[6944:6976]) and
// RSA-PKCS#1 v1.5 / SHA-256 with the §15 signing key. Verified structure-by-
// structure against a real decrypted aml_encrypt output.

// blPrefixLen is the per-BL header+signature region that precedes the body:
// 16 B zero (MAC slot) + 384 B signed header + 256 B RSA signature.
const blPrefixLen = 16 + 384 + 256 // 656

// buildBLPrefix builds the 656-byte signed prefix for a BL payload from the
// body's metadata. The plaintext payload is buildBLPrefix(...) || body.
//
// Signed header [16:400] (offsets relative to the 384-B header):
//
//	+0x00 "@AML"      +0x04 version=1
//	+0x10 body_size   +0x18 prefix_size (656)
//	+0x20 SHA-256(body)   +0x40 slot UUID (16 B)   +0x50 AES key (32 B)
//
// The RSA signature at [400:656] signs SHA-256 of that 384-B header.
func buildBLPrefix(bodySize int, bodySHA, uuid, aesKey []byte, key *rsa.PrivateKey) ([]byte, error) {
	if len(bodySHA) != 32 || len(uuid) != 16 || len(aesKey) != 32 {
		return nil, fmt.Errorf("buildBLPrefix: bad field sizes (sha=%d uuid=%d aes=%d)",
			len(bodySHA), len(uuid), len(aesKey))
	}
	h := make([]byte, 384)
	copy(h[0:4], "@AML")
	binary.LittleEndian.PutUint32(h[4:8], 1)
	binary.LittleEndian.PutUint64(h[0x10:], uint64(bodySize))
	binary.LittleEndian.PutUint64(h[0x18:], blPrefixLen)
	copy(h[0x20:0x40], bodySHA)
	copy(h[0x40:0x50], uuid)
	copy(h[0x50:0x70], aesKey)

	sum := sha256.Sum256(h)
	sig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, sum[:])
	if err != nil {
		return nil, fmt.Errorf("BL signature: %w", err)
	}
	out := make([]byte, blPrefixLen)
	copy(out[16:400], h)
	copy(out[400:656], sig)
	return out, nil
}

// signBL builds the full plaintext payload (prefix || body) for one BL.
// Caller AES-encrypts the result (zero IV) into the FIP body.
func signBL(body, uuid, aesKey []byte, key *rsa.PrivateKey) ([]byte, error) {
	s := sha256.Sum256(body)
	prefix, err := buildBLPrefix(len(body), s[:], uuid, aesKey, key)
	if err != nil {
		return nil, err
	}
	return append(prefix, body...), nil
}
