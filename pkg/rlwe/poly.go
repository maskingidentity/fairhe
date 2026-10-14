package rlwe

import (
	"math/big"
	"math/bits"

	"github.com/tuneinsight/lattigo/v6/ring"
)

// Ring elements are ring.Poly values in the coefficient domain (RNS limbs,
// residues in [0, q_i)). Small polynomials (ternary secrets, errors and the
// plaintext operands) are []int64 of length N with centred coefficients.

// NewPoly returns the zero element of R_Q.
func (p *Params) NewPoly() ring.Poly { return p.ringQ.NewPoly() }

// FromSmall maps centred integer coefficients into R_Q.
func (p *Params) FromSmall(v []int64) ring.Poly {
	out := p.ringQ.NewPoly()
	for i, qi := range p.lit.Q {
		c := out.Coeffs[i]
		for j, x := range v {
			c[j] = reduceInt64(x, qi)
		}
	}
	return out
}

// FromBig maps integer coefficients of any sign into R_Q.
func (p *Params) FromBig(v []*big.Int) ring.Poly {
	out := p.ringQ.NewPoly()
	p.ringQ.SetCoefficientsBigint(v, out)
	return out
}

// ToBig returns the coefficients of a in [0, Q).
func (p *Params) ToBig(a ring.Poly) []*big.Int {
	out := make([]*big.Int, p.N())
	p.ringQ.PolyToBigint(a, 1, out)
	return out
}

// Coeff returns coefficient j of a in [0, Q).
func (p *Params) Coeff(a ring.Poly, j int) *big.Int { return p.coeffOf(a, j) }

// Copy returns a deep copy of a.
func (p *Params) Copy(a ring.Poly) ring.Poly { return *a.CopyNew() }

// Add returns a + b.
func (p *Params) Add(a, b ring.Poly) ring.Poly {
	out := p.ringQ.NewPoly()
	p.ringQ.Add(a, b, out)
	return out
}

// Sub returns a - b.
func (p *Params) Sub(a, b ring.Poly) ring.Poly {
	out := p.ringQ.NewPoly()
	p.ringQ.Sub(a, b, out)
	return out
}

// Neg returns -a.
func (p *Params) Neg(a ring.Poly) ring.Poly {
	out := p.ringQ.NewPoly()
	p.ringQ.Neg(a, out)
	return out
}

// Mul returns a * b in R_Q through the NTT.
func (p *Params) Mul(a, b ring.Poly) ring.Poly {
	r := p.ringQ
	na, nb := r.NewPoly(), r.NewPoly()
	r.NTT(a, na)
	r.NTT(b, nb)
	r.MulCoeffsBarrett(na, nb, na)
	r.INTT(na, na)
	return na
}

// MulSmall returns a * s for a small polynomial s.
func (p *Params) MulSmall(a ring.Poly, s []int64) ring.Poly { return p.Mul(a, p.FromSmall(s)) }

// AddToCoeff adds the integer v to coefficient j of a in place.
func (p *Params) AddToCoeff(a ring.Poly, j int, v *big.Int) {
	t := new(big.Int)
	for i, qi := range p.lit.Q {
		q := new(big.Int).SetUint64(qi)
		d := t.Mod(v, q).Uint64()
		a.Coeffs[i][j] = addMod(a.Coeffs[i][j], d, qi)
	}
}

// ProductCoeff returns coefficient j of a * s in [0, Q) for a small s,
// computed as the negacyclic inner product
//
//	(a s)_j = sum_{i <= j} a_i s_{j-i} - sum_{i > j} a_i s_{N+j-i},
//
// without an NTT: the seller's partial decryption needs only this one
// coefficient.
func (p *Params) ProductCoeff(a ring.Poly, s []int64, j int) *big.Int {
	N := p.N()
	acc := p.ringQ.NewPoly() // only coefficient 0 of each limb is used
	for li, qi := range p.lit.Q {
		var sum uint64
		ai := a.Coeffs[li]
		for i := 0; i < N; i++ {
			k := j - i
			neg := false
			if k < 0 {
				k += N
				neg = true
			}
			sk := s[k]
			if sk == 0 {
				continue
			}
			if sk < 0 {
				sk = -sk
				neg = !neg
			}
			term := ai[i]
			if sk != 1 {
				term = mulMod(term, uint64(sk)%qi, qi)
			}
			if neg {
				sum = subMod(sum, term, qi)
			} else {
				sum = addMod(sum, term, qi)
			}
		}
		acc.Coeffs[li][0] = sum
	}
	return p.coeffOf(acc, 0)
}

func reduceInt64(x int64, q uint64) uint64 {
	if x >= 0 {
		return uint64(x) % q
	}
	r := uint64(-x) % q
	if r == 0 {
		return 0
	}
	return q - r
}

func addMod(a, b, q uint64) uint64 {
	s := a + b
	if s >= q {
		s -= q
	}
	return s
}

func subMod(a, b, q uint64) uint64 {
	if a >= b {
		return a - b
	}
	return a + q - b
}

func mulMod(a, b, q uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	return bits.Rem64(hi, lo, q)
}
