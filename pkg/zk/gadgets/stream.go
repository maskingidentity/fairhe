package gadgets

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

func init() { solver.RegisterHint(splitHint) }

// splitHint returns (v mod 2^k, v >> k) for the inputs (v, k).
func splitHint(_ *big.Int, in, out []*big.Int) error {
	k := uint(in[1].Uint64())
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), k), big.NewInt(1))
	out[0].And(in[0], mask)
	out[1].Rsh(in[0], k)
	return nil
}

// PackStream returns the stream packing of hashes.PackStream for values of
// bits bits into elements of capacity c, and range checks every value to
// [0, 2^bits) on the way: a value inside one element is checked whole, a
// value across a boundary is split by a hint into two pieces that are
// checked to their sizes and recombined. The packing therefore doubles as
// the range check of the values.
func PackStream(api frontend.API, rg *Ranger, vals []frontend.Variable, bits, c int) []frontend.Variable {
	var out []frontend.Variable
	var terms []frontend.Variable
	fill := 0
	emit := func() {
		out = append(out, sum(api, terms))
		terms, fill = nil, 0
	}
	shifted := func(v frontend.Variable, pos int) frontend.Variable {
		if pos == 0 {
			return v
		}
		return api.Mul(v, new(big.Int).Lsh(big.NewInt(1), uint(pos)))
	}
	for _, v := range vals {
		if fill+bits <= c {
			rg.Bits(v, bits)
			terms = append(terms, shifted(v, fill))
			fill += bits
			if fill == c {
				emit()
			}
			continue
		}
		take := c - fill
		parts, err := api.Compiler().NewHint(splitHint, 2, v, take)
		if err != nil {
			panic(err)
		}
		low, high := parts[0], parts[1]
		rg.Bits(low, take)
		rg.Bits(high, bits-take)
		api.AssertIsEqual(v, api.Add(low, api.Mul(high, new(big.Int).Lsh(big.NewInt(1), uint(take)))))
		terms = append(terms, shifted(low, fill))
		emit()
		terms = append(terms, high)
		fill = bits - take
		if fill == c {
			emit()
		}
	}
	if fill > 0 {
		emit()
	}
	return out
}

// DigestPoly returns the digest of a polynomial with coefficients in
// [0, 2^bits), stream-packed, the counterpart of hashes.DigPoly; it range
// checks the coefficients.
func DigestPoly(api frontend.API, rg *Ranger, label string, coeffs []frontend.Variable, bits int) (frontend.Variable, error) {
	f, err := FieldOf(api)
	if err != nil {
		return nil, err
	}
	return Digest(api, label, PackStream(api, rg, coeffs, bits, f.Capacity()))
}
