package main

import (
	_ "embed"
	"encoding/binary"
	"fmt"
)

// stage1Prefix is the immutable head of a stage-1 FIP, captured once from a
// known-good vendor build (board odroid-c4 + our TF-A 2.14): it spans
// [0 : 0x86570] = BL2 passthrough (inert in our flow) + the master-header
// skeleton + the DDR-fw gap + slot0/SCP. None of it changes per build — the
// DDR PHY firmware and Amlogic SCP are fixed silicon support. signNative
// rebuilds + re-signs everything inside it, so it's carried, never trusted.
//
//go:embed assets/stage1-prefix.bin
var stage1Prefix []byte

// defaultBL31 is the TF-A 2.14 raw binary (bl31.bin) the FIP body uses by
// default. Override with `sign -bl31 <your-bl31.bin>` to ship a custom BL31.
//
//go:embed assets/bl31.bin
var defaultBL31 []byte

const (
	// stage1PrefixEnd == len(stage1Prefix); the BL31 payload begins here
	// (relative offset 0x76570 inside the FIP region).
	stage1PrefixEnd = 0x86570
	// payloadAlign: each BL payload (656-byte signed prefix + body) is padded
	// so its total length is a multiple of 512 — matching vendor bootmk.
	payloadAlign = 512
)

// patchEntry sets payload slot j's offset+size in the FIP master header (hdr is
// the 0x4000-byte header region). Offsets are relative to the FIP region base.
func patchEntry(hdr []byte, j int, off, size uint64) {
	e := 0x20 + 40*j
	binary.LittleEndian.PutUint64(hdr[e+0x10:], off)
	binary.LittleEndian.PutUint64(hdr[e+0x18:], size)
}

// padBody zero-pads body so the whole payload (blPrefixLen + len) is a multiple
// of payloadAlign, reproducing the vendor's per-BL alignment.
func padBody(body []byte) []byte {
	rem := (blPrefixLen + len(body)) % payloadAlign
	if rem == 0 {
		return body
	}
	out := make([]byte, len(body)+(payloadAlign-rem))
	copy(out, body)
	return out
}

// wrapPayload builds a source-FIP payload region: a 656-byte zero prefix (which
// signNative discards and rebuilds from scratch) followed by the padded body.
func wrapPayload(body []byte) []byte {
	out := make([]byte, blPrefixLen)
	return append(out, padBody(body)...)
}

// assembleStage1 builds a stage-1 FIP (the structure signNative consumes) purely
// in Go — no aml_encrypt_g12a, build-fip.sh, or amlogic-boot-fip clone. It
// carries the immutable prefix and appends the BL31 (TF-A) + BL33 (u-boot)
// payloads, patching the master-header entries to match. signNative then
// re-signs/encrypts the result with the Spotify production key.
//
// bl31 may be nil to use the embedded default TF-A 2.14.
func assembleStage1(bl33, bl31 []byte) ([]byte, error) {
	if len(bl33) == 0 {
		return nil, fmt.Errorf("empty BL33 (u-boot)")
	}
	if len(stage1Prefix) != stage1PrefixEnd {
		return nil, fmt.Errorf("embedded stage1-prefix is %d bytes, expected %d", len(stage1Prefix), stage1PrefixEnd)
	}
	if len(bl31) == 0 {
		bl31 = defaultBL31
	}

	bl31region := wrapPayload(bl31)
	bl33region := wrapPayload(bl33)

	out := make([]byte, 0, len(stage1Prefix)+len(bl31region)+len(bl33region))
	out = append(out, stage1Prefix...)
	out = append(out, bl31region...)
	out = append(out, bl33region...)

	// Patch the master-header payload entries (offsets relative to fipRegionBase).
	hdr := out[fipRegionBase : fipRegionBase+masterHeaderLen]
	const bl31Off = stage1PrefixEnd - fipRegionBase // 0x76570
	patchEntry(hdr, 1, bl31Off, uint64(len(bl31region)))
	bl33Off := uint64(bl31Off) + uint64(len(bl31region))
	patchEntry(hdr, 2, bl33Off, 0) // BL32 absent; offset == BL33's
	patchEntry(hdr, 3, bl33Off, uint64(len(bl33region)))
	return out, nil
}
