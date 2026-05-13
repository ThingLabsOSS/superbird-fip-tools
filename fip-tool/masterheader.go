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

// The 16 KB master FIP header is the source stage-1 header copied verbatim with
// a handful of fields patched, then AES-256-CBC (zero IV) encrypted in place.
// Verified byte-exact (incl. the master RSA signature and the ciphertext)
// against a real aml_encrypt_g12a --bootsig output.

const (
	masterHeaderLen = 0x4000 // 16 KB
	masterSigOff    = 0x3f00 // RSA sig region [0x3f00:0x4000]
	masterSigHashTo = 16128  // sig covers header[16:16128]
	keyDataLen      = 1036   // @KEY data section copied into info-blocks
)

// info-block bases inside the master header (392 + 1128*i).
var infoBlockBase = [4]int{0x188, 0x5f0, 0xa58, 0xec0}

// perSlotParams are the fixed 32-byte [+0x08:+0x28] parameter blocks (load/run/
// size) for each slot on the Car Thing G12A. The source header already carries
// the right values for the populated slots; aml_encrypt rewrites them anyway, so
// we write them unconditionally to stay byte-exact even when the source is stale.
var perSlotParams = [4][32]byte{
	mustHex32("0000100100000000000000000000000000000000000000000000000000000000"), // BL30
	mustHex32("0000100500000000000000000000000000000000000000000000000000000000"), // BL31
	mustHex32("0000300500000000000000320000000000003232000000000032000000010000"), // BL32 (empty)
	mustHex32("0000000100000000000000000000000000000000000000000000000000000000"), // BL33
}

func mustHex32(s string) [32]byte {
	var b [32]byte
	for i := 0; i < 32; i++ {
		fmt.Sscanf(s[2*i:2*i+2], "%02x", &b[i])
	}
	return b
}

// payloadEntry describes where a signed payload lands in the output FIP.
type payloadEntry struct {
	offset uint64 // relative to 0x10000 (the FIP region base)
	size   uint64 // 0 ⇒ slot absent (e.g. BL32)
}

// buildMasterHeader returns the encrypted 16 KB master header. srcHeader is the
// source FIP's plaintext header (its bytes [0x10000:0x14000]); entries give the
// post-signing offset/size of each of the 4 BL slots.
func buildMasterHeader(srcHeader []byte, entries [4]payloadEntry, bundle []byte) ([]byte, error) {
	if len(srcHeader) != masterHeaderLen {
		return nil, fmt.Errorf("buildMasterHeader: source header is %d bytes, want %d", len(srcHeader), masterHeaderLen)
	}
	key, err := ExtractRSAKey(bundle)
	if err != nil {
		return nil, err
	}
	aesKey, err := ExtractAESKey(bundle)
	if err != nil {
		return nil, err
	}
	keyData := buildKeyCert(key.N, key.E, make([]byte, 16))[88 : 88+keyDataLen]

	h := make([]byte, masterHeaderLen)
	copy(h, srcHeader)

	for j := 0; j < 4; j++ {
		e := 0x20 + 40*j
		binary.LittleEndian.PutUint64(h[e+0x10:], entries[j].offset)
		binary.LittleEndian.PutUint64(h[e+0x18:], entries[j].size)

		base := infoBlockBase[j]
		copy(h[base+0x08:base+0x28], perSlotParams[j][:])
		if entries[j].size == 0 {
			continue // absent slot (BL32): params only
		}
		binary.LittleEndian.PutUint32(h[base+0x28:], 0x100) // has_signature
		copy(h[base+0x2c:base+0x4c], aesKey)
		if j == 1 || j == 3 { // BL31/BL33 carry the @KEY data section
			copy(h[base+0x5c:base+0x5c+keyDataLen], keyData)
		}
	}

	sum := sha256.Sum256(h[16:masterSigHashTo])
	sig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, sum[:])
	if err != nil {
		return nil, fmt.Errorf("master signature: %w", err)
	}
	copy(h[masterSigOff:masterHeaderLen], sig)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	enc := make([]byte, masterHeaderLen)
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(enc, h)
	return enc, nil
}
