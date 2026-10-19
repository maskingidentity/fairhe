// Package evalc1 is the Case 1 evaluation proof pi_eval,
// proven by the seller and verified by the settlement contract over
// BLS12-381. For the order's ciphertext c (digest h_c), the
// buyer's registered key pk = (b, a) (digest h_pk) and data x = S opening
// Com(x), it proves that the deliverable D, digest h_D, is
//
//	c_san = c S_bar + (b v + e0, a v + e1) + (e_fl X^J, 0),
//	D = MS_qdel(Ext_J(c_san)),
//
// with v ternary, ||e0||, ||e1|| <= B_err and |e_fl| <= 2^sigma_fl, and
// that the blob polynomial of D's packed elements takes the value y_z at z
// (paper Sections 3.3 and 4.3). The order ID is a public input bound into the
// challenge.
package evalc1

import (
	"fmt"
	"math/big"

	"fairhe/pkg/zk/gadgets"

	"github.com/consensys/gnark/frontend"
)

// Labels of the digests and the commitment.
const (
	LabelHC  = "h_c"
	LabelHPk = "h_pk"
	LabelHD  = "h_D"
	LabelX   = "x"
)

// Config fixes the constants of one verification key.
type Config struct {
	N, M, J int      // ring degree, entries of S (support of S_bar), released coefficient
	Q, QDel *big.Int // modulus of the flood and delivery modulus
	QBits   int      // bit length of Q - 1: digest packing of c and pk
	DBits   int      // bit length of q_del - 1
	DPer    int      // D coefficients per blob element
	XBits   int      // bits of an entry of S
	XMax    *big.Int // if set, the largest entry of S (below 2^XBits)
	PtScale int64    // K_pt, the scale of the plaintext operand
	BErr    int64
	SigmaFl int
	// LBound bounds the quotient by Q of the product identity and of the
	// released coefficient: ||S_bar||_1 + N + 2 for the class.
	LBound *big.Int
}

// Circuit is pi_eval for Case 1.
type Circuit struct {
	OrderID frontend.Variable `gnark:",public"`
	HC      frontend.Variable `gnark:",public"`
	HPk     frontend.Variable `gnark:",public"`
	ComX    frontend.Variable `gnark:",public"`
	HD      frontend.Variable `gnark:",public"`
	Z       frontend.Variable `gnark:",public"`
	YZ      frontend.Variable `gnark:",public"`

	C0, C1, B, A []frontend.Variable // the ordered ciphertext and the buyer key
	X            []frontend.Variable // S
	Rho          frontend.Variable   // salt of Com(x)
	V, E0, E1    []frontend.Variable
	EFl          frontend.Variable
	CS1          []frontend.Variable // second component of c_san
	CS0J         frontend.Variable   // released coefficient of the first component
	Ell0         frontend.Variable   // its quotient by Q
	L, K         []frontend.Variable // quotients of the product identity
	D, W, R      []frontend.Variable // D_0, D_1[0..N-1]; wrap bits; rounding remainders

	cfg Config
}

// New returns an empty circuit of the configuration (for compilation).
func New(cfg Config) *Circuit {
	n := cfg.N
	mk := func(k int) []frontend.Variable { return make([]frontend.Variable, k) }
	return &Circuit{
		C0: mk(n), C1: mk(n), B: mk(n), A: mk(n), X: mk(cfg.M),
		V: mk(n), E0: mk(n), E1: mk(n), CS1: mk(n), L: mk(n), K: mk(n),
		D: mk(n + 1), W: mk(n + 1), R: mk(n + 1), cfg: cfg,
	}
}

// Define implements the relation.
func (c *Circuit) Define(api frontend.API) error {
	cfg := c.cfg
	n := cfg.N
	if len(c.C0) != n || len(c.X) != cfg.M || len(c.D) != n+1 {
		return fmt.Errorf("evalc1: circuit shape does not match the configuration")
	}
	rg := gadgets.NewRanger(api)

	// The ordered ciphertext and the registered key, through their digests
	// (the stream packing range checks every coefficient to QBits bits).
	hc, err := gadgets.DigestPoly(api, rg, LabelHC, append(append([]frontend.Variable{}, c.C0...), c.C1...), cfg.QBits)
	if err != nil {
		return err
	}
	api.AssertIsEqual(hc, c.HC)
	hpk, err := gadgets.DigestPoly(api, rg, LabelHPk, append(append([]frontend.Variable{}, c.B...), c.A...), cfg.QBits)
	if err != nil {
		return err
	}
	api.AssertIsEqual(hpk, c.HPk)

	// The data in the agreed input range, opening Com(x).
	for _, x := range c.X {
		rg.Entry(x, cfg.XBits, cfg.XMax)
	}
	rg.Bits(c.Rho, 128)
	com, err := gadgets.Commitment(api, LabelX, c.X, cfg.XBits, c.Rho)
	if err != nil {
		return err
	}
	api.AssertIsEqual(com, c.ComX)

	// Bounded re-randomisation and flood.
	berr := big.NewInt(cfg.BErr)
	for i := 0; i < n; i++ {
		gadgets.Ternary(api, c.V[i])
		rg.InSym(c.E0[i], berr)
		rg.InSym(c.E1[i], berr)
	}
	rg.InSym(c.EFl, new(big.Int).Lsh(big.NewInt(1), uint(cfg.SigmaFl)))

	// S_bar: coefficient M-1-k is K_pt S_k.
	sbar := make([]frontend.Variable, cfg.M)
	support := make([]int, cfg.M)
	for k, x := range c.X {
		sbar[k] = api.Mul(x, cfg.PtScale)
		support[k] = cfg.M - 1 - k
	}

	// Second component: c_san,1 = c1 S_bar + a v + e1 in R_Q, canonical.
	for i := 0; i < n; i++ {
		rg.Canonical(c.CS1[i], cfg.Q)
		rg.InSym(c.L[i], cfg.LBound)
	}
	ch := gadgets.NewChecker(api, n)
	ch.Add(gadgets.Identity{
		Products: []gadgets.Term{
			{A: gadgets.Dense(c.C1), B: gadgets.Sparse(sbar, support)},
			{A: gadgets.Dense(c.A), B: gadgets.Dense(c.V)},
		},
		Add: []gadgets.Poly{gadgets.Dense(c.E1)},
		Sub: []gadgets.Poly{gadgets.Dense(c.CS1)},
		Q:   cfg.Q, L: gadgets.Dense(c.L), K: gadgets.Dense(c.K),
	})
	ch.Bind(c.OrderID, c.HC, c.HPk, c.ComX, c.HD, c.Z, c.YZ)
	ch.Finalize()

	// Released coefficient of the first component:
	// c_san,0[J] = (c0 S_bar)_J + (b v)_J + e0_J + e_fl - Q ell0.
	terms := make([]frontend.Variable, 0, cfg.M)
	for k := range sbar {
		idx := cfg.J - support[k]
		if idx >= 0 {
			terms = append(terms, api.Mul(c.C0[idx], sbar[k]))
		} else {
			terms = append(terms, api.Neg(api.Mul(c.C0[n+idx], sbar[k])))
		}
	}
	inner := api.Add(0, 0, terms...)
	bv := gadgets.NegacyclicCoeff(api, c.B, c.V, cfg.J)
	rg.Canonical(c.CS0J, cfg.Q)
	rg.InSym(c.Ell0, cfg.LBound)
	api.AssertIsEqual(api.Add(inner, bv, c.E0[cfg.J], c.EFl), api.Add(c.CS0J, api.Mul(c.Ell0, cfg.Q)))

	// Switch to q_del: Q (D_j + q_del w_j) = q_del c_j + r_j, |r_j| <= Q/2,
	// D_j in [0, q_del), w_j a bit.
	halfQ := new(big.Int).Rsh(cfg.Q, 1)
	for j := 0; j <= n; j++ {
		cj := c.CS0J
		if j > 0 {
			cj = c.CS1[j-1]
		}
		rg.Canonical(c.D[j], cfg.QDel)
		api.AssertIsBoolean(c.W[j])
		rg.InSym(c.R[j], halfQ)
		lhs := api.Mul(cfg.Q, api.Add(c.D[j], api.Mul(c.W[j], cfg.QDel)))
		api.AssertIsEqual(lhs, api.Add(api.Mul(cfg.QDel, cj), c.R[j]))
	}

	// The deliverable's blob: packed elements, their digest and evaluation.
	elems := gadgets.Pack(api, c.D, cfg.DBits, cfg.DPer)
	hd, err := gadgets.Digest(api, LabelHD, elems)
	if err != nil {
		return err
	}
	api.AssertIsEqual(hd, c.HD)
	y, err := gadgets.BlobEval(api, elems, c.Z)
	if err != nil {
		return err
	}
	api.AssertIsEqual(y, c.YZ)
	return nil
}
