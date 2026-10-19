// Package gadgets holds the circuit building blocks of the proofs:
// exact closed-interval range checks, ternary and
// canonical-representative checks, polynomial identities over Z[X] checked
// at a committed random point, single coefficients of negacyclic products,
// digests and packing, and the blob's barycentric evaluation. All
// challenges and lookup range checks share one commitment through gnark's
// multicommit, as the Solidity verifiers accept a single commitment.
package gadgets

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

// Ranger performs range checks with gnark's commitment-based (log-derivative
// lookup) range checker.
type Ranger struct {
	api frontend.API
	rc  frontend.Rangechecker
}

// NewRanger returns the range checker of the circuit (one lookup table is
// shared by all calls).
func NewRanger(api frontend.API) *Ranger {
	return &Ranger{api: api, rc: rangecheck.New(api)}
}

// Bits asserts 0 <= v < 2^bits for the integer representative of v.
func (r *Ranger) Bits(v frontend.Variable, bits int) {
	if bits <= 0 {
		r.api.AssertIsEqual(v, 0)
		return
	}
	r.rc.Check(v, bits)
}

// InRange asserts lo <= v <= hi exactly, for integer constants lo <= hi
// (possibly negative), by two checks v - lo, hi - v in [0, 2^b) with
// b = bitlen(hi - lo): both hold only on the closed interval, since 2^(b+1)
// is far below the field order.
func (r *Ranger) InRange(v frontend.Variable, lo, hi *big.Int) {
	width := new(big.Int).Sub(hi, lo)
	if width.Sign() < 0 {
		panic("gadgets: empty interval")
	}
	if width.Sign() == 0 {
		r.api.AssertIsEqual(v, lo)
		return
	}
	b := width.BitLen()
	r.rc.Check(r.api.Sub(v, lo), b)
	r.rc.Check(r.api.Sub(hi, v), b)
}

// Entry asserts 0 <= v <= max exactly when max is set (max < 2^bits), and
// 0 <= v < 2^bits otherwise.
func (r *Ranger) Entry(v frontend.Variable, bits int, max *big.Int) {
	if max == nil {
		r.Bits(v, bits)
		return
	}
	if max.BitLen() > bits {
		panic("gadgets: entry bound above the bit width")
	}
	r.InRange(v, big.NewInt(0), max)
}

// InSym asserts -bound <= v <= bound.
func (r *Ranger) InSym(v frontend.Variable, bound *big.Int) {
	r.InRange(v, new(big.Int).Neg(bound), bound)
}

// Canonical asserts 0 <= v < m, the canonical representative modulo m.
func (r *Ranger) Canonical(v frontend.Variable, m *big.Int) {
	r.InRange(v, big.NewInt(0), new(big.Int).Sub(m, big.NewInt(1)))
}

// Ternary asserts v in {-1, 0, 1} by v (v - 1) (v + 1) = 0.
func Ternary(api frontend.API, v frontend.Variable) {
	api.AssertIsEqual(api.Mul(v, api.Sub(api.Mul(v, v), 1)), 0)
}
