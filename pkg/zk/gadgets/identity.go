package gadgets

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/multicommit"
)

// Poly is a polynomial of the circuit: coefficient variables, dense
// (Coeffs[i] is the coefficient of X^i) or sparse (Coeffs[k] is the
// coefficient of X^Support[k]; every other coefficient is zero by
// construction of the relation).
type Poly struct {
	Coeffs  []frontend.Variable
	Support []int
}

// Dense wraps a dense coefficient slice.
func Dense(c []frontend.Variable) Poly { return Poly{Coeffs: c} }

// Sparse wraps coefficients at the given exponents.
func Sparse(c []frontend.Variable, support []int) Poly {
	if len(c) != len(support) {
		panic("gadgets: sparse polynomial with mismatched support")
	}
	return Poly{Coeffs: c, Support: support}
}

func (p Poly) degreeBound() int {
	if p.Support == nil {
		return len(p.Coeffs)
	}
	m := 0
	for _, e := range p.Support {
		if e+1 > m {
			m = e + 1
		}
	}
	return m
}

// Term is a signed product A B of two polynomials.
type Term struct {
	A, B Poly
	Neg  bool
}

// Identity is the polynomial identity over Z[X]
//
//	sum_t (+/-) A_t B_t + sum Add - sum Sub = Q L + (X^N + 1) K,
//
// which, with every coefficient of the left side and of Q L bounded far
// below half the field order (ensured by the range checks of the caller),
// holds over F_p[X] only if the left side reduced modulo X^N + 1 is Q L
// over the integers, i.e. the relation holds in R_Q. K needs no range check:
// it disappears in the reduction modulo X^N + 1. Q may be nil (no modular
// reduction, L empty).
type Identity struct {
	Products []Term
	Add, Sub []Poly
	Q        *big.Int
	L, K     Poly
}

// Checker collects polynomial identities of ring degree N and checks them at
// one random point r, derived from a commitment to every coefficient
// involved and to the bound values (public inputs among them, which gnark
// hashes into the challenge), so the prover fixes all of them before r.
type Checker struct {
	api   frontend.API
	n     int
	ids   []Identity
	bound []frontend.Variable
}

// NewChecker returns a checker for ring degree n.
func NewChecker(api frontend.API, n int) *Checker {
	return &Checker{api: api, n: n}
}

// Add schedules an identity.
func (c *Checker) Add(id Identity) { c.ids = append(c.ids, id) }

// Bind adds values to the commitment from which r is derived.
func (c *Checker) Bind(vars ...frontend.Variable) { c.bound = append(c.bound, vars...) }

// Finalize registers the commitment callback; call it once, after Add.
func (c *Checker) Finalize() {
	if len(c.ids) == 0 {
		return
	}
	seen := map[*frontend.Variable]bool{}
	var committed []frontend.Variable
	collect := func(p Poly) {
		if len(p.Coeffs) == 0 || seen[&p.Coeffs[0]] {
			return
		}
		seen[&p.Coeffs[0]] = true
		committed = append(committed, p.Coeffs...)
	}
	for _, id := range c.ids {
		for _, t := range id.Products {
			collect(t.A)
			collect(t.B)
			if t.A.degreeBound() > c.n || t.B.degreeBound() > c.n {
				panic("gadgets: factor of degree N or more")
			}
		}
		for _, p := range id.Add {
			collect(p)
		}
		for _, p := range id.Sub {
			collect(p)
		}
		collect(id.L)
		collect(id.K)
	}
	committed = append(committed, c.bound...)
	n := c.n
	ids := c.ids
	multicommit.WithCommitment(c.api, func(api frontend.API, r frontend.Variable) error {
		pw := Powers(api, r, n+1) // r^0 .. r^N
		cache := map[*frontend.Variable]frontend.Variable{}
		eval := func(p Poly) frontend.Variable {
			if len(p.Coeffs) == 0 {
				return 0
			}
			if v, ok := cache[&p.Coeffs[0]]; ok {
				return v
			}
			v := evalAt(api, p, pw)
			cache[&p.Coeffs[0]] = v
			return v
		}
		rN1 := api.Add(pw[n], 1)
		for _, id := range ids {
			var lhs frontend.Variable = 0
			for _, t := range id.Products {
				prod := api.Mul(eval(t.A), eval(t.B))
				if t.Neg {
					lhs = api.Sub(lhs, prod)
				} else {
					lhs = api.Add(lhs, prod)
				}
			}
			for _, p := range id.Add {
				lhs = api.Add(lhs, eval(p))
			}
			for _, p := range id.Sub {
				lhs = api.Sub(lhs, eval(p))
			}
			var rhs frontend.Variable = api.Mul(rN1, eval(id.K))
			if id.Q != nil {
				rhs = api.Add(rhs, api.Mul(id.Q, eval(id.L)))
			}
			api.AssertIsEqual(lhs, rhs)
		}
		return nil
	}, committed...)
}

// Powers returns r^0 .. r^(k-1).
func Powers(api frontend.API, r frontend.Variable, k int) []frontend.Variable {
	pw := make([]frontend.Variable, k)
	pw[0] = 1
	if k > 1 {
		pw[1] = r
	}
	for i := 2; i < k; i++ {
		pw[i] = api.Mul(pw[i-1], r)
	}
	return pw
}

// evalAt returns sum_k c_k r^e_k for the powers pw (one multiplication per
// coefficient; the sum is linear).
func evalAt(api frontend.API, p Poly, pw []frontend.Variable) frontend.Variable {
	terms := make([]frontend.Variable, len(p.Coeffs))
	for k, c := range p.Coeffs {
		e := k
		if p.Support != nil {
			e = p.Support[k]
		}
		if e >= len(pw) {
			panic("gadgets: polynomial degree beyond the powers")
		}
		terms[k] = api.Mul(c, pw[e])
	}
	return sum(api, terms)
}

// NegacyclicCoeff returns coefficient j of a s modulo X^N + 1 over the
// integers, sum_{i<=j} a_i s_{j-i} - sum_{i>j} a_i s_{N+j-i}, for dense a
// and s of length N (one multiplication per coefficient of a).
func NegacyclicCoeff(api frontend.API, a, s []frontend.Variable, j int) frontend.Variable {
	n := len(a)
	if len(s) != n {
		panic("gadgets: operands of different lengths")
	}
	pos := make([]frontend.Variable, 0, j+1)
	neg := make([]frontend.Variable, 0, n-j-1)
	for i := 0; i < n; i++ {
		if i <= j {
			pos = append(pos, api.Mul(a[i], s[j-i]))
		} else {
			neg = append(neg, api.Mul(a[i], s[n+j-i]))
		}
	}
	return api.Sub(sum(api, pos), sum(api, neg))
}

func sum(api frontend.API, terms []frontend.Variable) frontend.Variable {
	switch len(terms) {
	case 0:
		return 0
	case 1:
		return terms[0]
	case 2:
		return api.Add(terms[0], terms[1])
	}
	return api.Add(terms[0], terms[1], terms[2:]...)
}
