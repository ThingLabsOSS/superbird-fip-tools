package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// slot0 (BL30 / SCP) is signed and encrypted differently from BL31/BL33. Instead
// of the per-BL @KEY+656-sig prefix (see bootsig.go), it gets a "keymax-prefixed"
// Stage-1 structure built by aml_bl30_bl40_sig_file, then the whole thing is
// encrypted with the g12 "m3" chunked AES (aml_file_aes_m3) rather than the
// plain whole-region CBC used elsewhere. Verified byte-exact (incl. the RSA
// signature) against a real aml_encrypt_g12a --bootsig output.
//
// Stage-1 plaintext layout (file offsets):
//
//	[0:2264]      keymax  (amluserkey[4680:6944] verbatim; [0:16] = unsigned nonce)
//	[2264:2328]   @AML 64-byte header
//	[2328:2584]   RSA-2048 signature (lower half of a 512-B reserved region)
//	[2584:2840]   zero (upper half of the sig region — IS hashed)
//	[2840:3964]   @KEY user-pubkey Montgomery cert (1124 B)
//	[3964:4096]   zero pad (key region is 1256 B total)
//	[4096:4096+v29] BL30 body, zero-padded to a 512-B boundary (v29)
//
// The signature covers SHA-256( hdr[0:64] || stage1[2584:4096+v29] ): the 64-B
// header, then everything from the top of the sig region through the body, with
// the 256-B signature itself skipped.
const (
	bl30KeymaxLen  = 2264 // root keymax prefix
	bl30HdrLen     = 64   // @AML Stage-1 header
	bl30SigLen     = 256  // RSA-2048 signature length
	bl30SigRegion  = 512  // reserved signature region
	bl30KeyDataLen = 1256 // @KEY cert region (1124-B cert + pad)
	bl30BodyOff    = 1832 // body offset within the post-keymax (v43) buffer
	m3ChunkSize    = 2048
)

// keymaxOffset/keymaxEnd bound the root keymax block inside the amluserkey blob.
const (
	keymaxOffset = 4680
	keymaxEnd    = 6944
)

// extractKeymax returns the 2264-byte root keymax block from the amluserkey blob.
func extractKeymax(bundle []byte) ([]byte, error) {
	if len(bundle) < keymaxEnd {
		return nil, fmt.Errorf("keybundle too short for keymax (%d bytes)", len(bundle))
	}
	return bundle[keymaxOffset:keymaxEnd], nil
}

// m3Crypt implements aml_file_aes_m3: AES-256-CBC in independent 2048-byte
// chunks, each starting from a fresh zero IV. The input must be 16-byte aligned.
func m3Crypt(data, key []byte, encrypt bool) ([]byte, error) {
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("m3Crypt: input not 16-byte aligned (%d)", len(data))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += m3ChunkSize {
		end := i + m3ChunkSize
		if end > len(data) {
			end = len(data)
		}
		iv := make([]byte, aes.BlockSize) // fresh zero IV per chunk
		if encrypt {
			cipher.NewCBCEncrypter(block, iv).CryptBlocks(out[i:end], data[i:end])
		} else {
			cipher.NewCBCDecrypter(block, iv).CryptBlocks(out[i:end], data[i:end])
		}
	}
	return out, nil
}

// buildBL30Stage1 assembles the plaintext Stage-1 BL30 image: keymax prefix +
// @AML header + RSA signature + @KEY cert + padded body. nonce overwrites the
// first 16 bytes of the keymax (it is not covered by any signature).
func buildBL30Stage1(body, keymax, keyCert, nonce []byte, key *rsa.PrivateKey) ([]byte, error) {
	if len(keymax) != bl30KeymaxLen {
		return nil, fmt.Errorf("buildBL30Stage1: keymax is %d bytes, want %d", len(keymax), bl30KeymaxLen)
	}
	if len(nonce) != 16 {
		return nil, fmt.Errorf("buildBL30Stage1: nonce is %d bytes, want 16", len(nonce))
	}
	if len(keyCert) > bl30KeyDataLen {
		return nil, fmt.Errorf("buildBL30Stage1: keyCert %d > key region %d", len(keyCert), bl30KeyDataLen)
	}

	v29 := (len(body) + 511) &^ 511 // body padded up to a 512-B boundary
	v43 := make([]byte, bl30BodyOff+v29)

	// @AML 64-byte header (all fields deterministic given v29).
	h := v43[0:bl30HdrLen]
	binary.LittleEndian.PutUint32(h[0x00:], 0x4C4D4140) // "@AML"
	binary.LittleEndian.PutUint32(h[0x04:], uint32(bl30BodyOff+v29))
	h[0x08] = bl30HdrLen
	binary.LittleEndian.PutUint16(h[0x0A:], 0x0101) // version
	binary.LittleEndian.PutUint32(h[0x10:], 1)      // mode = signed
	binary.LittleEndian.PutUint32(h[0x14:], bl30HdrLen)
	binary.LittleEndian.PutUint32(h[0x18:], bl30SigRegion)
	binary.LittleEndian.PutUint32(h[0x1C:], bl30HdrLen+bl30SigLen) // key_block_offset = 320
	binary.LittleEndian.PutUint32(h[0x20:], 2)                     // key_size_flag
	binary.LittleEndian.PutUint32(h[0x24:], bl30HdrLen+bl30SigRegion)
	binary.LittleEndian.PutUint32(h[0x28:], bl30KeyDataLen)
	binary.LittleEndian.PutUint32(h[0x2C:], uint32(bl30BodyOff+v29-bl30HdrLen-bl30SigLen))
	binary.LittleEndian.PutUint32(h[0x34:], bl30BodyOff)
	binary.LittleEndian.PutUint32(h[0x38:], uint32(v29))

	keyOff := bl30HdrLen + bl30SigRegion // 576
	copy(v43[keyOff:keyOff+len(keyCert)], keyCert)
	copy(v43[bl30BodyOff:], body)

	// Sign SHA-256( hdr[0:64] || v43[320:] ): the sig itself (v43[64:320]) is
	// skipped; the zero upper half of the sig region (v43[320:576]) is hashed.
	hsh := sha256.New()
	hsh.Write(v43[0:bl30HdrLen])
	hsh.Write(v43[bl30HdrLen+bl30SigLen:])
	sum := hsh.Sum(nil)
	sig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, sum)
	if err != nil {
		return nil, fmt.Errorf("BL30 signature: %w", err)
	}
	copy(v43[bl30HdrLen:bl30HdrLen+bl30SigLen], sig)

	out := make([]byte, bl30KeymaxLen+len(v43))
	copy(out, keymax)
	copy(out[0:16], nonce)
	copy(out[bl30KeymaxLen:], v43)
	return out, nil
}

// buildSlot0 produces the final, m3-encrypted BL30 payload ready to drop into a
// FIP at the slot0 offset. ts is the 16-byte @KEY timestamp (informational; not
// verified). nonce (16 B) overwrites the keymax head and is not signed.
func buildSlot0(body, bundle, nonce, ts []byte) ([]byte, error) {
	key, err := ExtractRSAKey(bundle)
	if err != nil {
		return nil, err
	}
	aesKey, err := ExtractAESKey(bundle)
	if err != nil {
		return nil, err
	}
	keymax, err := extractKeymax(bundle)
	if err != nil {
		return nil, err
	}
	keyCert := buildKeyCert(key.N, key.E, ts)
	stage1, err := buildBL30Stage1(body, keymax, keyCert, nonce, key)
	if err != nil {
		return nil, err
	}
	return m3Crypt(stage1, aesKey, true)
}
