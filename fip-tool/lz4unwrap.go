package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// Amlogic "LZ4C" container — the wrapper aml_encrypt_g12a emits for
// "--bl3sig --type bl33 --compress lz4" (and what BL31 decompresses at
// runtime). It is plain LZ4 block format (liblz4 1.7.6) behind a small
// custom header. Layout of the compressed BL33 payload inside its @AML
// FIP section:
//
//	descriptor (lz4cDescLen bytes):
//	  +0x00  "LZ4C"
//	  +0x04  u32  block_max    uncompressed bytes per block — always 0x00800000 (8 MiB)
//	  +0x08  u32  ucomp        total decompressed size
//	  +0x0c  u32  comp         total compressed size (summed over blocks)
//	  +0x10  sha256[32]        digest of the decompressed image
//	  +0x30  char[]            build timestamp ("YYYYMMDDhh:mm:ss"), NUL-padded
//	per block:
//	  "LZ4C" + 32-byte block signature (lz4cBlockHdr bytes), then a raw LZ4
//	  block decoding to min(block_max, remaining) bytes. Blocks chain as an
//	  LZ4 stream: block N's matches may reach up to 64 KiB back into block
//	  N-1's output, so they decode against one contiguous buffer.
//
// The descriptor's block_max == 0x00800000 distinguishes it from the
// per-block "LZ4C" (whose following 4 bytes are a random signature), which
// is how findLZ4CDescriptor locates it in a decrypted FIP.
const (
	lz4cMagic    = "LZ4C"
	lz4cBlockMax = 0x00800000 // descriptor block_max sentinel
	lz4cDescLen  = 0x5c       // descriptor size (magic..timestamp)
	lz4cBlockHdr = 0x24       // "LZ4C" + 32-byte block signature
)

// lz4cInfo summarizes a decompressed LZ4C container.
type lz4cInfo struct {
	Ucomp     int
	Comp      int
	Timestamp string
	Verified  bool // true if the embedded SHA-256 was present and matched
}

// lz4BlockDecode decodes one raw LZ4 block from src[sp:], appending to dst
// until limit bytes have been produced for this block. Match offsets may
// reach before this block's start (into dst's existing tail) so chained
// stream blocks decode correctly. Returns the grown buffer and the new src
// position.
func lz4BlockDecode(src []byte, sp int, dst []byte, limit int) ([]byte, int, error) {
	base := len(dst)
	n := len(src)
	for sp < n && len(dst)-base < limit {
		token := int(src[sp])
		sp++
		litlen := token >> 4
		if litlen == 15 {
			for {
				if sp >= n {
					return nil, 0, fmt.Errorf("lz4: truncated literal length")
				}
				b := int(src[sp])
				sp++
				litlen += b
				if b != 255 {
					break
				}
			}
		}
		if sp+litlen > n {
			return nil, 0, fmt.Errorf("lz4: literal run overruns input")
		}
		dst = append(dst, src[sp:sp+litlen]...)
		sp += litlen
		if len(dst)-base >= limit {
			break // final sequence of a block is literals-only
		}
		if sp+2 > n {
			break
		}
		offset := int(src[sp]) | int(src[sp+1])<<8
		sp += 2
		if offset == 0 {
			return nil, 0, fmt.Errorf("lz4: zero match offset")
		}
		mlen := token & 0xf
		if mlen == 15 {
			for {
				if sp >= n {
					return nil, 0, fmt.Errorf("lz4: truncated match length")
				}
				b := int(src[sp])
				sp++
				mlen += b
				if b != 255 {
					break
				}
			}
		}
		mlen += 4 // LZ4 minmatch
		mstart := len(dst) - offset
		if mstart < 0 {
			return nil, 0, fmt.Errorf("lz4: match offset %d before buffer start", offset)
		}
		// Byte-at-a-time copy: handles overlapping (RLE) matches where
		// offset < mlen.
		for i := 0; i < mlen; i++ {
			dst = append(dst, dst[mstart+i])
		}
	}
	return dst, sp, nil
}

// findLZ4CDescriptors returns the offsets of every candidate LZ4C container
// descriptor in a decrypted FIP body — "LZ4C" markers whose block_max field is
// the 8 MiB sentinel. Padding / mis-decrypted regions can produce spurious
// hits, so callers verify each by decoding (the descriptor carries a SHA-256).
func findLZ4CDescriptors(pt []byte) []int {
	var offs []int
	magic := []byte(lz4cMagic)
	for i := 0; i+8 <= len(pt); i++ {
		if bytes.Equal(pt[i:i+4], magic) &&
			binary.LittleEndian.Uint32(pt[i+4:]) == lz4cBlockMax {
			offs = append(offs, i)
		}
	}
	return offs
}

// findLZ4CDescriptor returns the first candidate descriptor offset, or -1.
func findLZ4CDescriptor(pt []byte) int {
	if offs := findLZ4CDescriptors(pt); len(offs) > 0 {
		return offs[0]
	}
	return -1
}

// decompressLZ4C decompresses the Amlogic LZ4C container whose descriptor
// starts at desc in pt, verifying the embedded SHA-256 of the plaintext.
func decompressLZ4C(pt []byte, desc int) ([]byte, lz4cInfo, error) {
	if desc < 0 || desc+lz4cDescLen > len(pt) || string(pt[desc:desc+4]) != lz4cMagic {
		return nil, lz4cInfo{}, fmt.Errorf("lz4c: no descriptor magic at 0x%x", desc)
	}
	blockMax := int(binary.LittleEndian.Uint32(pt[desc+4:]))
	ucomp := int(binary.LittleEndian.Uint32(pt[desc+8:]))
	comp := int(binary.LittleEndian.Uint32(pt[desc+12:]))
	want := pt[desc+0x10 : desc+0x30]
	tsRaw := pt[desc+0x30 : desc+lz4cDescLen]
	if i := bytes.IndexByte(tsRaw, 0); i >= 0 {
		tsRaw = tsRaw[:i] // NUL-terminated C string
	}
	ts := string(tsRaw)
	if blockMax <= 0 {
		blockMax = ucomp
	}

	out := make([]byte, 0, ucomp)
	pos := desc + lz4cDescLen // first block header
	streamBytes := 0          // compressed stream bytes consumed (excl. block headers)
	for len(out) < ucomp {
		if pos+lz4cBlockHdr > len(pt) || string(pt[pos:pos+4]) != lz4cMagic {
			return nil, lz4cInfo{}, fmt.Errorf("lz4c: expected block header at 0x%x", pos)
		}
		pos += lz4cBlockHdr
		chunk := ucomp - len(out)
		if chunk > blockMax {
			chunk = blockMax
		}
		start := pos
		var err error
		out, pos, err = lz4BlockDecode(pt, pos, out, chunk)
		if err != nil {
			return nil, lz4cInfo{}, err
		}
		streamBytes += pos - start
	}
	if len(out) != ucomp {
		return nil, lz4cInfo{}, fmt.Errorf("lz4c: decoded %d bytes, descriptor said %d", len(out), ucomp)
	}
	// Structural check: the compressed stream must consume exactly `comp`
	// bytes. This catches a bad descriptor / wrong offset even when the
	// SHA-256 field is absent.
	if streamBytes != comp {
		return nil, lz4cInfo{}, fmt.Errorf("lz4c: consumed %d compressed bytes, descriptor said %d", streamBytes, comp)
	}
	info := lz4cInfo{Ucomp: ucomp, Comp: comp, Timestamp: ts}
	if bytes.Equal(want, make([]byte, 32)) {
		// Some build/OTA paths leave the digest field zero — nothing to
		// verify against, but the byte-exact decode above stands on its own.
		info.Verified = false
	} else if got := sha256.Sum256(out); !bytes.Equal(got[:], want) {
		return nil, lz4cInfo{}, fmt.Errorf("lz4c: SHA-256 mismatch (got %x, want %x)", got[:], want)
	} else {
		info.Verified = true
	}
	return out, info, nil
}

// extractBL33 decompresses the LZ4C-wrapped BL33 (u-boot) from a decrypted
// FIP body / bootloader plaintext.
func extractBL33(pt []byte) ([]byte, lz4cInfo, error) {
	cands := findLZ4CDescriptors(pt)
	if len(cands) == 0 {
		return nil, lz4cInfo{}, fmt.Errorf("no LZ4C container found (is BL33 compressed?)")
	}
	// Padding can yield spurious "LZ4C"+sentinel hits; accept the first that
	// decodes and passes its embedded SHA-256.
	var lastErr error
	for _, desc := range cands {
		out, info, err := decompressLZ4C(pt, desc)
		if err == nil {
			return out, info, nil
		}
		lastErr = err
	}
	return nil, lz4cInfo{}, fmt.Errorf("found %d LZ4C candidate(s), none verified: %w", len(cands), lastErr)
}

// ubootVersion returns the "U-Boot <version>" banner embedded in an image, or
// "" if absent.
func ubootVersion(b []byte) string {
	i := bytes.Index(b, []byte("U-Boot 20"))
	if i < 0 {
		return ""
	}
	end := i
	for end < len(b) && end < i+80 && b[end] >= 0x20 {
		end++
	}
	return string(b[i:end])
}
