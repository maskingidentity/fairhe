package hashes

import (
	"fmt"
	"math/big"
)

// PackStream packs unsigned values of exactly bits bits into field elements
// as one little-endian bit stream: value i occupies stream bits
// [i bits, (i+1) bits) and element k holds stream bits [k C, (k+1) C) with
// C = Capacity. A value that straddles an element boundary is split there.
// This is the packing of polynomial digests (h_c, h_pk, h_c21): it fills
// every element, where coefficient-aligned packing of 134-bit coefficients
// would waste 120 of the 254 bits.
func PackStream(f Field, vals []*big.Int, bits int) ([]*big.Int, error) {
	C := f.Capacity()
	if bits < 1 || bits > C {
		return nil, fmt.Errorf("hashes: cannot stream %d-bit values into %s", bits, f)
	}
	out := make([]*big.Int, 0, (len(vals)*bits+C-1)/C)
	acc := new(big.Int)
	fill := 0
	for _, v := range vals {
		if v.Sign() < 0 || v.BitLen() > bits {
			return nil, fmt.Errorf("hashes: value %s does not fit %d bits", v, bits)
		}
		consumed := 0
		for consumed < bits {
			take := min(bits-consumed, C-fill)
			piece := new(big.Int).Rsh(v, uint(consumed))
			piece.And(piece, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(take)), big.NewInt(1)))
			acc.Or(acc, piece.Lsh(piece, uint(fill)))
			fill += take
			consumed += take
			if fill == C {
				out = append(out, acc)
				acc, fill = new(big.Int), 0
			}
		}
	}
	if fill > 0 {
		out = append(out, acc)
	}
	return out, nil
}

// StreamElements returns the number of elements PackStream produces.
func StreamElements(f Field, n, bits int) int {
	C := f.Capacity()
	return (n*bits + C - 1) / C
}

// DigPoly returns the digest of a polynomial with coefficients in
// [0, 2^bits), stream-packed: H_dig(label; PackStream(coeffs)).
func DigPoly(f Field, label string, coeffs []*big.Int, bits int) (*big.Int, error) {
	elems, err := PackStream(f, coeffs, bits)
	if err != nil {
		return nil, err
	}
	return Dig(f, label, elems)
}
