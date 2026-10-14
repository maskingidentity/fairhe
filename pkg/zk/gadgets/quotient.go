package gadgets

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/tuneinsight/lattigo/v6/ring"
)

// Witness side of Identity: the exact quotients L and K over Z[X], computed
// from integer polynomials with a CRT ring of degree 2N whose modulus exceeds
// twice every coefficient, so the full product is exact.

// WTerm is a signed product of integer polynomials (coefficients of any
// sign, at most N each).
type WTerm struct {
	A, B []*big.Int
	Neg  bool
}

// Quotients returns L (length N) and K (length N) with
//
//	sum_t (+/-) A_t B_t + sum add - sum sub = Q L + (X^N + 1) K
//
// over Z[X], or an error if the left side is not zero in R_Q (or, with q
// nil, not zero modulo X^N + 1).
func Quotients(n int, q *big.Int, terms []WTerm, add, sub [][]*big.Int) (L, K []*big.Int, err error) {
	P := make([]*big.Int, 2*n)
	for i := range P {
		P[i] = new(big.Int)
	}
	for _, t := range terms {
		prod, err := FullProduct(n, t.A, t.B)
		if err != nil {
			return nil, nil, err
		}
		for i, c := range prod {
			if t.Neg {
				P[i].Sub(P[i], c)
			} else {
				P[i].Add(P[i], c)
			}
		}
	}
	// Reduce modulo X^N + 1: P = P_low + X^N P_high = (P_low - P_high) + (X^N + 1) P_high.
	K = make([]*big.Int, n)
	R := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		K[i] = new(big.Int).Set(P[n+i])
		R[i] = new(big.Int).Sub(P[i], P[n+i])
	}
	for _, a := range add {
		for i, c := range a {
			R[i].Add(R[i], c)
		}
	}
	for _, s := range sub {
		for i, c := range s {
			R[i].Sub(R[i], c)
		}
	}
	L = make([]*big.Int, n)
	rem := new(big.Int)
	for i := range R {
		if q == nil {
			if R[i].Sign() != 0 {
				return nil, nil, fmt.Errorf("gadgets: identity fails at coefficient %d", i)
			}
			L[i] = new(big.Int)
			continue
		}
		L[i], _ = new(big.Int).QuoRem(R[i], q, rem)
		if rem.Sign() != 0 {
			return nil, nil, fmt.Errorf("gadgets: coefficient %d is not a multiple of Q", i)
		}
	}
	return L, K, nil
}

// FullProduct returns the exact product a b in Z[X] (2N coefficients, the
// last zero) for integer polynomials of at most N coefficients.
func FullProduct(n int, a, b []*big.Int) ([]*big.Int, error) {
	if len(a) > n || len(b) > n {
		return nil, fmt.Errorf("gadgets: operand longer than N")
	}
	cr, err := crtRingFor(n)
	if err != nil {
		return nil, err
	}
	bound := new(big.Int).Mul(maxAbs(a), l1(b))
	if new(big.Int).Lsh(bound, 1).Cmp(cr.modulus) >= 0 {
		return nil, fmt.Errorf("gadgets: product of 2^%d exceeds the CRT modulus", bound.BitLen())
	}
	r := cr.ring
	pa, pb := r.NewPoly(), r.NewPoly()
	r.SetCoefficientsBigint(a, pa)
	r.SetCoefficientsBigint(b, pb)
	r.NTT(pa, pa)
	r.NTT(pb, pb)
	r.MulCoeffsBarrett(pa, pb, pa)
	r.INTT(pa, pa)
	out := make([]*big.Int, 2*n)
	for i := range out {
		out[i] = new(big.Int)
	}
	r.PolyToBigintCentered(pa, 1, out)
	return out, nil
}

type crtRing struct {
	ring    *ring.Ring
	modulus *big.Int
}

var crtRings sync.Map // n -> *crtRing

// crtRingFor returns the ring of degree 2n over four ~60-bit primes
// p = 1 mod 4n (a 240-bit modulus): the product of degree 2n - 2 does not
// wrap around, and every coefficient of the relations stays below 2^200.
func crtRingFor(n int) (*crtRing, error) {
	if v, ok := crtRings.Load(n); ok {
		return v.(*crtRing), nil
	}
	m := big.NewInt(int64(4 * n))
	j := new(big.Int).Lsh(big.NewInt(1), 60)
	j.Sub(j, big.NewInt(2)).Div(j, m)
	var primes []uint64
	for len(primes) < 4 {
		p := new(big.Int).Mul(j, m)
		p.Add(p, big.NewInt(1))
		if p.ProbablyPrime(30) {
			primes = append(primes, p.Uint64())
		}
		j.Sub(j, big.NewInt(1))
	}
	r, err := ring.NewRing(2*n, primes)
	if err != nil {
		return nil, err
	}
	cr := &crtRing{ring: r, modulus: r.Modulus()}
	crtRings.Store(n, cr)
	return cr, nil
}

func maxAbs(v []*big.Int) *big.Int {
	m := new(big.Int)
	for _, x := range v {
		if a := new(big.Int).Abs(x); a.Cmp(m) > 0 {
			m = a
		}
	}
	return m
}

func l1(v []*big.Int) *big.Int {
	s := new(big.Int)
	for _, x := range v {
		s.Add(s, new(big.Int).Abs(x))
	}
	return s
}

// Ints converts int64 coefficients to big integers.
func Ints(v []int64) []*big.Int {
	out := make([]*big.Int, len(v))
	for i, x := range v {
		out[i] = big.NewInt(x)
	}
	return out
}
