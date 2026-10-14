// Package evalc2 is the Case 2 evaluation proof pi_eval,
// proven by the buyer with each order and verified by the seller off-chain
// over BN254, before it applies its key: the weights w are in the class and
// open Com(f), and the ordered c2,1 is the second component of the
// re-randomised evaluation (paper eq. (3)),
//
//	c2,1 = w_hat c1,1 + a v + e1',  v ternary,  ||e1'||_inf <= B_err.
//
// One circuit, hence one verification key, serves the whole class: w is a
// witness (paper Section 3.6). c2,1, c1,1 and a are public inputs as
// polynomials.
package evalc2

import (
	"fmt"
	"math/big"

	"fairhe/pkg/hashes"
	"fairhe/pkg/rlwe"
	"fairhe/pkg/zk/gadgets"
	"fairhe/pkg/zk/valclass"

	"github.com/consensys/gnark/frontend"
)

// Config fixes the constants of one verification key.
type Config struct {
	N       int
	Q       *big.Int
	PtScale int64
	BErr    int64
	Class   valclass.Class
	// LBound bounds the quotient by Q: ||w_hat||_1 max + N + 2.
	LBound *big.Int
}

// ConfigFor returns the configuration of a Case 2 parameter set.
func ConfigFor(p *rlwe.Params, cl valclass.Class) (Config, error) {
	if p.Case() != rlwe.Case2 {
		return Config{}, fmt.Errorf("evalc2: parameters of case %d", p.Case())
	}
	lb := new(big.Int).Mul(cl.WHatNormL1Max(), big.NewInt(p.PtScale()))
	lb.Add(lb, big.NewInt(int64(p.N()+2)))
	return Config{N: p.N(), Q: p.Q(), PtScale: p.PtScale(), BErr: int64(p.BErr()), Class: cl, LBound: lb}, nil
}

// Circuit is pi_eval for Case 2.
type Circuit struct {
	C21, C11, A []frontend.Variable `gnark:",public"`
	ComF        frontend.Variable   `gnark:",public"`

	W     []frontend.Variable
	RhoF  frontend.Variable
	V, E1 []frontend.Variable
	L, K  []frontend.Variable

	cfg Config
}

// New returns an empty circuit of the configuration.
func New(cfg Config) *Circuit {
	mk := func(k int) []frontend.Variable { return make([]frontend.Variable, k) }
	n := cfg.N
	return &Circuit{C21: mk(n), C11: mk(n), A: mk(n), W: mk(cfg.Class.Cols), V: mk(n), E1: mk(n), L: mk(n), K: mk(n), cfg: cfg}
}

// Define implements the relation.
func (c *Circuit) Define(api frontend.API) error {
	cfg := c.cfg
	n, m := cfg.N, cfg.Class.M()
	if len(c.C21) != n || 2*m-1 > n {
		return fmt.Errorf("evalc2: circuit shape does not match the configuration")
	}
	rg := gadgets.NewRanger(api)
	wh, err := cfg.Class.Weights(api, rg, c.W, c.RhoF, c.ComF)
	if err != nil {
		return err
	}
	pt := make([]frontend.Variable, m) // w_hat(X): coefficient k is K_pt w_hat_k
	support := make([]int, m)
	for k := range wh {
		pt[k] = api.Mul(wh[k], cfg.PtScale)
		support[k] = k
	}
	berr := big.NewInt(cfg.BErr)
	for i := 0; i < n; i++ {
		gadgets.Ternary(api, c.V[i])
		rg.InSym(c.E1[i], berr)
		rg.InSym(c.L[i], cfg.LBound)
	}
	// w_hat c1,1 + a v + e1' - c2,1 = Q L + (X^N + 1) K
	ch := gadgets.NewChecker(api, n)
	ch.Add(gadgets.Identity{
		Products: []gadgets.Term{
			{A: gadgets.Dense(c.C11), B: gadgets.Sparse(pt, support)},
			{A: gadgets.Dense(c.A), B: gadgets.Dense(c.V)},
		},
		Add: []gadgets.Poly{gadgets.Dense(c.E1)},
		Sub: []gadgets.Poly{gadgets.Dense(c.C21)},
		Q:   cfg.Q, L: gadgets.Dense(c.L), K: gadgets.Dense(c.K),
	})
	ch.Bind(c.ComF)
	ch.Finalize()
	return nil
}

// Assign returns the assignment for an order: c2,1, the slot's c1,1 and a,
// the buyer's weights, commitment salt and re-randomisation witness.
func Assign(cfg Config, p *rlwe.Params, c21, c11, a []*big.Int, w []int64, rhoF []byte, rw *rlwe.ZeroEncWitness) (*Circuit, error) {
	wh := cfg.Class.Expand(w)
	pt := make([]*big.Int, cfg.N)
	for i := range pt {
		pt[i] = new(big.Int)
	}
	for k, x := range wh {
		pt[k] = big.NewInt(x * cfg.PtScale)
	}
	L, K, err := gadgets.Quotients(cfg.N, cfg.Q,
		[]gadgets.WTerm{{A: c11, B: pt}, {A: a, B: gadgets.Ints(rw.V)}},
		[][]*big.Int{gadgets.Ints(rw.E1)}, [][]*big.Int{c21})
	if err != nil {
		return nil, fmt.Errorf("evalc2: %w", err)
	}
	comF, err := cfg.Class.CommitF(hashes.BN254, w, rhoF)
	if err != nil {
		return nil, err
	}
	asg := New(cfg)
	for i := 0; i < cfg.N; i++ {
		asg.C21[i], asg.C11[i], asg.A[i] = c21[i], c11[i], a[i]
		asg.V[i], asg.E1[i], asg.L[i], asg.K[i] = rw.V[i], rw.E1[i], L[i], K[i]
	}
	for j, x := range w {
		asg.W[j] = x
	}
	asg.RhoF, asg.ComF = new(big.Int).SetBytes(rhoF), comF
	return asg, nil
}

// PublicAssignment returns the public part of the statement: c2,1, the
// slot's c1,1 and a, and Com(f).
func PublicAssignment(cfg Config, c21, c11, a []*big.Int, comF *big.Int) *Circuit {
	c := New(cfg)
	for i := 0; i < cfg.N; i++ {
		c.C21[i], c.C11[i], c.A[i] = c21[i], c11[i], a[i]
	}
	c.ComF = comF
	return c
}
