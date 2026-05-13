package main

import (
	"bytes"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
)

// Field offsets inside the Spotify production bundle aml-user-key.sig
// (6976-byte Amlogic keymax), reverse-engineered 2026-05-23. The bundle is
// plaintext; see the carthing-secure-boot memory for the full trail.
const (
	aesKeyOffset0 = 0x1173 // AES-256 key, copy 0
	aesKeyOffset1 = 0x1b20 // AES-256 key, copy 1 (redundant)
	aesKeySize    = 32

	// RSA signing key — the format aml_gx_load_rsa_key_file (0x405a0d) loads
	// for the 6976-byte bundle: 8 CRT components in fixed 552-byte slots,
	// each a *little-endian* MPI (the enc-rev notes say big-endian, but it's
	// empirically LE). Verified: P,Q prime, P·Q==N, E·D≡1, and a real FIP
	// signature RSA-verifies against this key. See [carthing-secure-boot].
	rsaModDwordsOff = 544  // uint32 LE: modulus length in 32-bit dwords (64 = RSA-2048)
	rsaNOff         = 0    // modulus N
	rsaEOff         = 552  // public exponent e (4 bytes)
	rsaDOff         = 1104 // private exponent D
	rsaPOff         = 1656 // prime P
	rsaQOff         = 2208 // prime Q
)

const expectedAESKeyHex = "ab6541be131018f71fbc266f4643ff0d7626f9ab4ee2077ab7fd63dc620c090d"

// findKeybundle locates aml-user-key.sig: the explicit path if non-empty,
// otherwise a few sensible spots relative to cwd and the executable.
func findKeybundle(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	cands := []string{
		"aml-user-key.sig",
		"keys/aml-user-key.sig",
		"../keys/aml-user-key.sig",
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		cands = append(cands,
			filepath.Join(dir, "keys", "aml-user-key.sig"),
			filepath.Join(dir, "..", "keys", "aml-user-key.sig"),
		)
	}
	for _, c := range cands {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("could not find aml-user-key.sig (looked in %v); pass --keybundle", cands)
}

func loadKeybundle(explicit string) ([]byte, error) {
	p, err := findKeybundle(explicit)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

// ExtractAESKey pulls the AES-256 key out of the bundle (two redundant copies,
// verified to agree).
func ExtractAESKey(bundle []byte) ([]byte, error) {
	if len(bundle) < aesKeyOffset1+aesKeySize {
		return nil, fmt.Errorf("keybundle too small (%d bytes)", len(bundle))
	}
	k0 := bundle[aesKeyOffset0 : aesKeyOffset0+aesKeySize]
	k1 := bundle[aesKeyOffset1 : aesKeyOffset1+aesKeySize]
	if !bytes.Equal(k0, k1) {
		return nil, fmt.Errorf("redundant AES key copies @%#x and @%#x differ; non-Spotify bundle?",
			aesKeyOffset0, aesKeyOffset1)
	}
	if hex.EncodeToString(k0) != expectedAESKeyHex {
		fmt.Fprintf(os.Stderr, "warning: extracted AES key %s != known production fingerprint\n",
			hex.EncodeToString(k0))
	}
	return append([]byte(nil), k0...), nil
}

// leToBig interprets b as a little-endian unsigned integer.
func leToBig(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

// ExtractRSAKey loads the FIP signing key from the bundle exactly as
// aml_gx_load_rsa_key_file does: the CRT components N/E/D/P/Q as little-endian
// MPIs in fixed 552-byte slots. n, dp, dq, qinv are recomputed/validated by Go.
func ExtractRSAKey(bundle []byte) (*rsa.PrivateKey, error) {
	if len(bundle) < rsaQOff+256 {
		return nil, fmt.Errorf("keybundle too small for RSA key (%d bytes)", len(bundle))
	}
	dwords := binary.LittleEndian.Uint32(bundle[rsaModDwordsOff : rsaModDwordsOff+4])
	nb := int(dwords) * 4 // modulus/D byte length (256 for RSA-2048)
	pb := nb / 2          // prime byte length
	if nb == 0 || rsaDOff+nb > len(bundle) || rsaQOff+pb > len(bundle) {
		return nil, fmt.Errorf("implausible modulus length %d dwords", dwords)
	}

	n := leToBig(bundle[rsaNOff : rsaNOff+nb])
	e := leToBig(bundle[rsaEOff : rsaEOff+4])
	d := leToBig(bundle[rsaDOff : rsaDOff+nb])
	p := leToBig(bundle[rsaPOff : rsaPOff+pb])
	q := leToBig(bundle[rsaQOff : rsaQOff+pb])

	if !e.IsInt64() || e.Int64() <= 0 || e.Int64() > (1<<31-1) {
		return nil, fmt.Errorf("implausible exponent %s", e)
	}
	key := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: n, E: int(e.Int64())},
		D:         d,
		Primes:    []*big.Int{p, q},
	}
	key.Precompute()
	if err := key.Validate(); err != nil { // checks P·Q==N and E·D≡1 (mod λ)
		return nil, fmt.Errorf("loaded RSA key invalid (bundle layout differs?): %w", err)
	}
	return key, nil
}
