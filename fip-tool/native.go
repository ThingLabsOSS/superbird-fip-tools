package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// signNative produces a fully self-signed FIP from a source stage-1 FIP (the
// bootmk / build-fip.sh output), with no call to the vendor aml_encrypt_g12a.
// It reproduces aml_encrypt's --bootsig output structure-for-structure:
//
//   - BL2 region [0:0x10000]: passed through unchanged. (Our flow always pairs
//     the FIP body with stock mask-ROM BL2, so this region is never used.)
//   - master header [0x10000:0x14000]: rebuilt + signed + AES-encrypted.
//   - DDR-fw gap [0x14000:0x78000]: carried from source, then the @DFM regions
//     are AES-CBC re-encrypted (the per-block second pass).
//   - payloads [0x78000:]: BL30 (m3, keymax-prefixed), BL31/BL33 (per-BL @AML
//     sign + CBC), BL32 absent.
//
// Header / gap / BL31 / BL33 are byte-exact vs the vendor tool; BL30 carries the
// full SCP body but pads it to its own 512-aligned size rather than reproducing
// the vendor's larger padding (functionally identical — BL2 loads per the size
// field). The output is self-consistent and verifiable; the final gate is a
// hardware boot.
const fipRegionBase = 0x10000

// per-slot @AML prefix UUIDs (the source payloads carry a zero UUID; the signer
// fills these standard TF-A FIP key-cert UUIDs in). BL31 / BL33 only.
var blUUID = map[int][]byte{
	1: mustHex16("47d4086d4cfe98469b952950cbbd5a00"),
	3: mustHex16("d6d0eea7fcead54b97829934f234b6e4"),
}

func mustHex16(s string) []byte {
	b := make([]byte, 16)
	for i := 0; i < 16; i++ {
		fmt.Sscanf(s[2*i:2*i+2], "%02x", &b[i])
	}
	return b
}

func srcEntry(hdr []byte, j int) (uint64, uint64) {
	e := 0x20 + 40*j
	return binary.LittleEndian.Uint64(hdr[e+0x10:]), binary.LittleEndian.Uint64(hdr[e+0x18:])
}

// cbcZeroIV AES-256-CBC encrypts pt in place (or a copy) with a zero IV.
func cbcZeroIV(dst, pt, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	n := len(pt) / aes.BlockSize * aes.BlockSize
	cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(dst[:n], pt[:n])
	copy(dst[n:], pt[n:])
	return nil
}

func signNative(source, bundle []byte) ([]byte, error) {
	if len(source) < 0x78000 {
		return nil, fmt.Errorf("source FIP too small (%d bytes)", len(source))
	}
	aesKey, err := ExtractAESKey(bundle)
	if err != nil {
		return nil, err
	}
	key, err := ExtractRSAKey(bundle)
	if err != nil {
		return nil, err
	}
	srcHdr := source[fipRegionBase : fipRegionBase+masterHeaderLen]

	// --- BL30: body lives after the source slot0's own 16-B + @AML framing ---
	so0, _ := srcEntry(srcHdr, 0)
	s0 := source[fipRegionBase+so0:]
	bl30BodyOff := 16 + int(binary.LittleEndian.Uint32(s0[16+0x34:])) // payload_offset
	// take the full remainder of the source slot0 (this matches the vendor's
	// signed body byte-for-byte; only the trailing pad length differs).
	srcSlot0Len := int(srcSlot0Size(srcHdr))
	bl30Body := s0[bl30BodyOff:srcSlot0Len]
	slot0, err := buildSlot0(bl30Body, bundle, make([]byte, 16), make([]byte, 16))
	if err != nil {
		return nil, fmt.Errorf("BL30: %w", err)
	}

	// --- BL31 / BL33: body = source payload past the 656-B prefix ---
	signBLSlot := func(j int) ([]byte, error) {
		o, sz := srcEntry(srcHdr, j)
		p := source[fipRegionBase+o : fipRegionBase+o+sz]
		signed, err := signBL(p[blPrefixLen:], blUUID[j], aesKey, key)
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(signed))
		if err := cbcZeroIV(out, signed, aesKey); err != nil {
			return nil, err
		}
		return out, nil
	}
	bl31, err := signBLSlot(1)
	if err != nil {
		return nil, fmt.Errorf("BL31: %w", err)
	}
	bl33, err := signBLSlot(3)
	if err != nil {
		return nil, fmt.Errorf("BL33: %w", err)
	}

	// --- layout: payloads packed from the source's slot0 offset (0x68000 rel) ---
	var ent [4]payloadEntry
	cur := so0
	ent[0] = payloadEntry{cur, uint64(len(slot0))}
	cur += uint64(len(slot0))
	ent[1] = payloadEntry{cur, uint64(len(bl31))}
	cur += uint64(len(bl31))
	ent[2] = payloadEntry{cur, 0} // BL32 absent; offset == BL33's
	ent[3] = payloadEntry{cur, uint64(len(bl33))}

	hdr, err := buildMasterHeader(srcHdr, ent, bundle)
	if err != nil {
		return nil, err
	}

	// --- assemble ---
	absBase := fipRegionBase + int(so0) // 0x78000
	out := make([]byte, absBase+len(slot0)+len(bl31)+len(bl33))
	copy(out, source[:fipRegionBase])                   // BL2 passthrough
	copy(out[fipRegionBase:], hdr)                      // master header
	copy(out[0x14000:absBase], source[0x14000:absBase]) // DDR-fw gap (carried)
	if err := dfmEncryptGap(out, srcHdr, aesKey); err != nil {
		return nil, err
	}
	p := absBase
	p += copy(out[p:], slot0)
	p += copy(out[p:], bl31)
	copy(out[p:], bl33)
	return out, nil
}

func srcSlot0Size(hdr []byte) uint64 {
	_, sz := srcEntry(hdr, 0)
	return sz
}

// dfmEncryptGap applies the @DFM second-pass: each declared region of the carried
// DDR-fw gap is AES-CBC (zero IV) re-encrypted in place.
func dfmEncryptGap(out, srcHdr, key []byte) error {
	const dfmOff = 0x1790
	if binary.LittleEndian.Uint32(srcHdr[dfmOff:]) != 0x4D464440 { // "@DFM"
		return nil
	}
	n := int(binary.LittleEndian.Uint16(srcHdr[dfmOff+4:]))
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	for k := 0; k < n; k++ {
		eo := dfmOff + 0x10 + 64*k
		off := binary.LittleEndian.Uint32(srcHdr[eo+8:])
		sz := binary.LittleEndian.Uint32(srcHdr[eo+12:])
		a := fipRegionBase + int(off)
		region := out[a : a+int(sz)]
		cipher.NewCBCEncrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(region, region)
	}
	return nil
}
