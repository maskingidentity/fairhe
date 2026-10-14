// Package member is the Case 1 membership proof pi_member,
// proven by the buyer with each order and verified by the seller off-chain
// over BLS12-381: the weights w are in the class (||w||_inf <= w_max) and
// open Com(f), and the ordered ciphertext encrypts w_hat under the secret
// of the registered key with bounded noise,
//
//	c0 + c1 s = K_enc w_hat + e_c,  ||e_c||_inf <= B_err,  s ternary,
//
// where s is the secret whose salted digest h_sB the key proof opened (paper
// Section 3.3.1, items 1 and 2). The ciphertext is a public input as
// polynomials.
package member

import (
	"fmt"
	"math/big"

	"fairhe/pkg/hashes"
	"fairhe/pkg/rlwe"
	"fairhe/pkg/zk/gadgets"
	"fairhe/pkg/zk/keyproof"
	"fairhe/pkg/zk/valclass"

	"github.com/consensys/gnark/frontend"
)

// Config fixes the constants of one verification key.
type Config struct {
	N     int
	Q     *big.Int
	KEnc  *big.Int // the scale of the encrypted message
	BErr  int64
	Class valclass.Class
}

// ConfigFor returns the configuration of a Case 1 parameter set.
func ConfigFor(p *rlwe.Params, cl valclass.Class) (Config, error) {
	if p.Case() != rlwe.Case1 {
		return Config{}, fmt.Errorf("member: parameters of case %d", p.Case())
	}
	return Config{N: p.N(), Q: p.Q(), KEnc: p.EncScale(), BErr: int64(p.BErr()), Class: cl}, nil
}

// Circuit is pi_member.
type Circuit struct {
	C0, C1 []frontend.Variable `gnark:",public"`
	ComF   frontend.Variable   `gnark:",public"`
	HSB    frontend.Variable   `gnark:",public"`

	W    []frontend.Variable
	RhoF frontend.Variable
	S, E []frontend.Variable
	Eta  frontend.Variable
	L, K []frontend.Variable

	cfg Config
}

// New returns an empty circuit of the configuration.
func New(cfg Config) *Circuit {
	mk := func(k int) []frontend.Variable { return make([]frontend.Variable, k) }
	n := cfg.N
	return &Circuit{C0: mk(n), C1: mk(n), W: mk(cfg.Class.Cols), S: mk(n), E: mk(n), L: mk(n), K: mk(n), cfg: cfg}
}

// Define implements the relation.
func (c *Circuit) Define(api frontend.API) error {
	cfg := c.cfg
	n, m := cfg.N, cfg.Class.M()
	if len(c.C0) != n || m > n {
		return fmt.Errorf("member: circuit shape does not match the configuration")
	}
	rg := gadgets.NewRanger(api)
	wh, err := cfg.Class.Weights(api, rg, c.W, c.RhoF, c.ComF)
	if err != nil {
		return err
	}
	msg := make([]frontend.Variable, m)
	support := make([]int, m)
	for k := range wh {
		msg[k] = api.Mul(wh[k], cfg.KEnc)
		support[k] = k
	}
	berr := big.NewInt(cfg.BErr)
	lb := big.NewInt(int64(n + 3))
	for i := 0; i < n; i++ {
		gadgets.Ternary(api, c.S[i])
		rg.InSym(c.E[i], berr)
		rg.InSym(c.L[i], lb)
	}
	// c1 s + c0 - e - K_enc w_hat = Q L + (X^N + 1) K
	ch := gadgets.NewChecker(api, n)
	ch.Add(gadgets.Identity{
		Products: []gadgets.Term{{A: gadgets.Dense(c.C1), B: gadgets.Dense(c.S)}},
		Add:      []gadgets.Poly{gadgets.Dense(c.C0)},
		Sub:      []gadgets.Poly{gadgets.Dense(c.E), gadgets.Sparse(msg, support)},
		Q:        cfg.Q, L: gadgets.Dense(c.L), K: gadgets.Dense(c.K),
	})
	ch.Bind(c.ComF, c.HSB)
	ch.Finalize()
	rg.Bits(c.Eta, 8*hashes.SaltBytes)
	h, err := gadgets.DigestSecret(api, keyproof.LabelBuyer, c.S, c.Eta)
	if err != nil {
		return err
	}
	api.AssertIsEqual(h, c.HSB)
	return nil
}

// Assign returns the assignment for an order: the ciphertext, the buyer's
// weights and commitment salt, its secret and salt, and the encryption
// error; with Com(f) and h_sB.
func Assign(cfg Config, p *rlwe.Params, ct *rlwe.Ciphertext, w []int64, rhoF []byte, s []int64, eta []byte, ew *rlwe.EncWitness) (*Circuit, error) {
	c0, c1 := p.ToBig(ct.C0), p.ToBig(ct.C1)
	wh := cfg.Class.Expand(w)
	msg := make([]*big.Int, cfg.N)
	for i := range msg {
		msg[i] = new(big.Int)
	}
	for k, x := range wh {
		msg[k].Mul(cfg.KEnc, big.NewInt(x))
	}
	L, K, err := gadgets.Quotients(cfg.N, cfg.Q, []gadgets.WTerm{{A: c1, B: gadgets.Ints(s)}},
		[][]*big.Int{c0}, [][]*big.Int{gadgets.Ints(ew.E), msg})
	if err != nil {
		return nil, fmt.Errorf("member: %w", err)
	}
	comF, err := cfg.Class.CommitF(hashes.BLS12381, w, rhoF)
	if err != nil {
		return nil, err
	}
	hsb, err := hashes.DigSecret(hashes.BLS12381, keyproof.LabelBuyer, s, eta)
	if err != nil {
		return nil, err
	}
	a := New(cfg)
	for i := 0; i < cfg.N; i++ {
		a.C0[i], a.C1[i], a.S[i], a.E[i], a.L[i], a.K[i] = c0[i], c1[i], s[i], ew.E[i], L[i], K[i]
	}
	for j, x := range w {
		a.W[j] = x
	}
	a.RhoF, a.ComF, a.HSB, a.Eta = new(big.Int).SetBytes(rhoF), comF, hsb, new(big.Int).SetBytes(eta)
	return a, nil
}

// PublicAssignment returns the public part of the statement: the ordered
// ciphertext, Com(f) and h_sB.
func PublicAssignment(cfg Config, p *rlwe.Params, ct *rlwe.Ciphertext, comF, hsb *big.Int) *Circuit {
	c := New(cfg)
	c0, c1 := p.ToBig(ct.C0), p.ToBig(ct.C1)
	for i := 0; i < cfg.N; i++ {
		c.C0[i], c.C1[i] = c0[i], c1[i]
	}
	c.ComF, c.HSB = comF, hsb
	return c
}
