package hashes

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"math/big"

	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	blsposeidon2 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"
	bnfr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bnposeidon2 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

// H_dig is Poseidon2 in the Merkle-Damgard mode of gnark-crypto (width 2,
// 6 full and 50 partial rounds, zero IV), whose in-circuit counterpart is
// gnark's std/hash/poseidon2 (the spike of spike_test.go
// measured 186 constraints per absorbed element on both fields against
// about 331 for MiMC). A digest is defined per scalar field, since a Case 1
// digest is recomputed in BLS12-381 circuits and a Case 2 digest in BN254
// circuits; a value digested in one field is never compared with the other.

// Field is the scalar field of the proof system that recomputes a digest.
type Field int

const (
	// BN254 is the field of the Case 2 circuits.
	BN254 Field = iota
	// BLS12381 is the field of the Case 1 circuits (and of the blob).
	BLS12381
)

func (f Field) String() string {
	if f == BN254 {
		return "bn254"
	}
	return "bls12-381"
}

// Modulus returns the order of the field.
func (f Field) Modulus() *big.Int {
	if f == BN254 {
		return bnfr.Modulus()
	}
	return blsfr.Modulus()
}

// Capacity returns the number of bits a packed element carries without
// reduction: 253 for BN254 (r > 2^253), 254 for BLS12-381 (r > 2^254).
func (f Field) Capacity() int {
	return f.Modulus().BitLen() - 1
}

func (f Field) hasher() hash.Hash {
	if f == BN254 {
		return bnposeidon2.NewMerkleDamgardHasher()
	}
	return blsposeidon2.NewMerkleDamgardHasher()
}

// DigTag returns the domain-tag element absorbed first by a digest of label
// over n elements: SHA-256(TagDig || enc(label) || n) mod r. Binding the
// count makes digests of different lengths independent; inside a circuit the
// tag is a constant.
func DigTag(f Field, label string, n int) *big.Int {
	h := sha256.New()
	h.Write([]byte(TagDig))
	writeLenPrefixed(h, []byte(label))
	h.Write(u64(uint64(n)))
	t := new(big.Int).SetBytes(h.Sum(nil))
	return t.Mod(t, f.Modulus())
}

// Dig returns H_dig(tag || e_1 || ... || e_n) over f for elements in [0, r).
func Dig(f Field, label string, elems []*big.Int) (*big.Int, error) {
	r := f.Modulus()
	h := f.hasher()
	var buf [32]byte
	write := func(e *big.Int) error {
		if e.Sign() < 0 || e.Cmp(r) >= 0 {
			return fmt.Errorf("hashes: element %s outside [0, r) of %s", e, f)
		}
		e.FillBytes(buf[:])
		_, err := h.Write(buf[:])
		return err
	}
	if err := write(DigTag(f, label, len(elems))); err != nil {
		return nil, err
	}
	for _, e := range elems {
		if err := write(e); err != nil {
			return nil, err
		}
	}
	return new(big.Int).SetBytes(h.Sum(nil)), nil
}

// PackBits packs unsigned values of at most bits bits each, k =
// floor(Capacity / bits) per element, little-endian within an element:
// e_j = sum_{i<k} v_{jk+i} 2^(bits i). The last element holds the remainder.
func PackBits(f Field, vals []*big.Int, bits int) ([]*big.Int, error) {
	k := f.Capacity() / bits
	if bits < 1 || k < 1 {
		return nil, fmt.Errorf("hashes: cannot pack %d-bit values into %s", bits, f)
	}
	out := make([]*big.Int, 0, (len(vals)+k-1)/k)
	for j := 0; j < len(vals); j += k {
		e := new(big.Int)
		for i := min(j+k, len(vals)) - 1; i >= j; i-- {
			v := vals[i]
			if v.Sign() < 0 || v.BitLen() > bits {
				return nil, fmt.Errorf("hashes: value %s does not fit %d bits", v, bits)
			}
			e.Lsh(e, uint(bits)).Or(e, v)
		}
		out = append(out, e)
	}
	return out, nil
}

// PackPerElement returns how many bits-bit values PackBits puts in one
// element of f.
func PackPerElement(f Field, bits int) int { return f.Capacity() / bits }

// SaltBytes is the length of a salt: lambda = 128 bits.
const SaltBytes = 16

// DigSecret returns the salted digest of a ternary secret,
// h_s = H_dig(s || eta), with the coefficients mapped to s_i + 1 in {0, 1, 2}
// and packed two bits each, and the 128-bit salt eta as the last element.
func DigSecret(f Field, label string, s []int64, eta []byte) (*big.Int, error) {
	if len(eta) != SaltBytes {
		return nil, fmt.Errorf("hashes: salt of %d bytes, want %d", len(eta), SaltBytes)
	}
	vals := make([]*big.Int, len(s))
	for i, x := range s {
		if x < -1 || x > 1 {
			return nil, fmt.Errorf("hashes: secret coefficient %d is not ternary", x)
		}
		vals[i] = big.NewInt(x + 1)
	}
	elems, err := PackBits(f, vals, 2)
	if err != nil {
		return nil, err
	}
	return Dig(f, label, append(elems, new(big.Int).SetBytes(eta)))
}

// Commit returns the salted hash commitment
// Com(v) = H_dig(pack(v) || rho) under the label "com." + label, for
// unsigned values of at most bits bits and a 128-bit salt rho. It is hiding
// in the random-oracle model and binding by collision resistance.
func Commit(f Field, label string, vals []*big.Int, bits int, rho []byte) (*big.Int, error) {
	if len(rho) != SaltBytes {
		return nil, fmt.Errorf("hashes: salt of %d bytes, want %d", len(rho), SaltBytes)
	}
	elems, err := PackBits(f, vals, bits)
	if err != nil {
		return nil, err
	}
	return Dig(f, "com."+label, append(elems, new(big.Int).SetBytes(rho)))
}

// Bytes32 returns the 32-byte big-endian encoding of a digest, the form in
// which the ledger records it.
func Bytes32(d *big.Int) [32]byte {
	var out [32]byte
	d.FillBytes(out[:])
	return out
}
