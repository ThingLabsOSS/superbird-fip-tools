package main

import (
	"encoding/binary"
	"math/big"
)

// buildKeyCert builds the 1124-byte Amlogic "@KEY" Montgomery RSA-pubkey cert
// for an RSA-2048 key, byte-identical to aml_create_key_from_file_x's output.
//
// Layout (RSA-2048): 48-B header + 5×8-B id table + data section. The data is
// the u-boot-style Montgomery public key: little-endian modulus N (256 B in a
// 512-B field, zero-padded), exponent e, rr = R²mod N (R = 2^2048, LE), then
// n0inv = -N⁻¹ mod 2³² and the modulus length in 32-bit words. ts is the
// 16-byte "YYYYMMDDHHMMSS.." build timestamp baked into the header.
func buildKeyCert(n *big.Int, e int, ts []byte) []byte {
	const lenWords = 64 // RSA-2048 = 64 little-endian 32-bit words

	blk := make([]byte, 1124)
	copy(blk[0:4], "@KEY")
	binary.LittleEndian.PutUint32(blk[4:8], 1124)   // total_block_size
	blk[8] = 1                                      // version
	blk[9] = 2                                      // key_count (encoded as R2SA)
	blk[10] = 48                                    // payload_offset (lo)
	copy(blk[0xC:0x10], "R2SA")                     // type_magic
	blk[0x10] = 5                                   // num_id_entries
	blk[0x11] = 8                                   // id_entry_size
	binary.LittleEndian.PutUint16(blk[0x14:], 624)  // payload_offset
	binary.LittleEndian.PutUint16(blk[0x16:], 1076) // payload_size
	binary.LittleEndian.PutUint16(blk[0x18:], 664)  // data_offset
	binary.LittleEndian.PutUint16(blk[0x1A:], 1036) // data_size
	copy(blk[0x20:0x30], ts)                        // 16-B timestamp

	// id-entry table @0x30: {type, offset (rel payload_off=48), length, rsvd}
	ids := [5][3]uint16{{1, 40, 512}, {2, 552, 4}, {9, 556, 512}, {13, 1068, 4}, {2, 1072, 4}}
	for i, en := range ids {
		o := 0x30 + 8*i
		binary.LittleEndian.PutUint16(blk[o:], en[0])
		binary.LittleEndian.PutUint16(blk[o+2:], en[1])
		binary.LittleEndian.PutUint16(blk[o+4:], en[2])
	}

	// data section
	putLE(blk[88:88+256], n) // modulus (LE), high 256 B left zero
	binary.LittleEndian.PutUint32(blk[600:], uint32(e))
	r := new(big.Int).Lsh(big.NewInt(1), lenWords*32) // R = 2^2048
	rr := r.Mod(r.Mul(r, r), n)                       // rr = R² mod N
	putLE(blk[604:604+256], rr)
	binary.LittleEndian.PutUint32(blk[1116:], montN0inv(n))
	binary.LittleEndian.PutUint32(blk[1120:], lenWords)
	return blk
}

// putLE writes x into buf as a little-endian unsigned integer, zero-padded.
func putLE(buf []byte, x *big.Int) {
	be := x.Bytes() // big-endian, minimal length
	for i := 0; i < len(be) && i < len(buf); i++ {
		buf[i] = be[len(be)-1-i]
	}
}

// montN0inv returns -N⁻¹ mod 2³² (the Montgomery n0' helper).
func montN0inv(n *big.Int) uint32 {
	mod := new(big.Int).Lsh(big.NewInt(1), 32) // 2³²
	inv := new(big.Int).ModInverse(new(big.Int).Mod(n, mod), mod)
	neg := new(big.Int).Mod(new(big.Int).Sub(mod, inv), mod)
	return uint32(neg.Uint64())
}
