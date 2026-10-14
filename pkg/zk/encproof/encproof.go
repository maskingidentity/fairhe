// Package encproof is the Case 2 data-ciphertext proof pi_enc, proven by
// the seller once per slot and verified by the buyer
// off-chain over BN254: the data S are in the agreed input range and open
// Com(x), and c1 encrypts S_bar under the slot secret with bounded noise,
//
//	c1,0 + c1,1 s = K_enc S_bar + e,  ||e||_inf <= B_err,  s ternary,
//
// where s is the secret whose salted digest h_s the slot's pi_key and
// pi_dec open (paper Section 3.4.2, item 3). c1 is a public input as
// polynomials.
package encproof

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
	KEnc  *big.Int
	BErr  int64
	Class valclass.Class
}

// ConfigFor returns the configuration of a Case 2 parameter set.
func ConfigFor(p *rlwe.Params, cl valclass.Class) (Config, error) {
	if p.Case() != rlwe.Case2 {
		return Config{}, fmt.Errorf("encproof: parameters of case %d", p.Case())
	}
	return Config{N: p.N(), Q: p.Q(), KEnc: p.EncScale(), BErr: int64(p.BErr()), Class: cl}, nil
}

// Circuit is pi_enc.
type Circuit struct {
	C10, C11 []frontend.Variable `gnark:",public"`
	ComX     frontend.Variable   `gnark:",public"`
	HS       frontend.Variable   `gnark:",public"`

	X    []frontend.Variable
	RhoX frontend.Variable
	S, E []frontend.Variable
	Eta  frontend.Variable
	L, K []frontend.Variable

	cfg Config
}

// New returns an empty circuit of the configuration.
func New(cfg Config) *Circuit {
	mk := func(k int) []frontend.Variable { return make([]frontend.Variable, k) }
	n := cfg.N
	return &Circuit{C10: mk(n), C11: mk(n), X: mk(cfg.Class.M()), S: mk(n), E: mk(n), L: mk(n), K: mk(n), cfg: cfg}
}

// Define implements the relation.
func (c *Circuit) Define(api frontend.API) error {
	cfg := c.cfg
	n, m := cfg.N, cfg.Class.M()
	if len(c.C10) != n || len(c.X) != m || 2*m-1 > n {
		return fmt.Errorf("encproof: circuit shape does not match the configuration")
	}
	rg := gadgets.NewRanger(api)
	if err := cfg.Class.Data(api, rg, c.X, c.RhoX, c.ComX); err != nil {
		return err
	}
	msg := make([]frontend.Variable, m) // S_bar: coefficient m-1-k is K_enc S_k
	support := make([]int, m)
	for k, x := range c.X {
		msg[k] = api.Mul(x, cfg.KEnc)
		support[k] = m - 1 - k
	}
	berr := big.NewInt(cfg.BErr)
	lb := big.NewInt(int64(n + 3))
	for i := 0; i < n; i++ {
		gadgets.Ternary(api, c.S[i])
		rg.InSym(c.E[i], berr)
		rg.InSym(c.L[i], lb)
	}
	ch := gadgets.NewChecker(api, n)
	ch.Add(gadgets.Identity{
		Products: []gadgets.Term{{A: gadgets.Dense(c.C11), B: gadgets.Dense(c.S)}},
		Add:      []gadgets.Poly{gadgets.Dense(c.C10)},
		Sub:      []gadgets.Poly{gadgets.Dense(c.E), gadgets.Sparse(msg, support)},
		Q:        cfg.Q, L: gadgets.Dense(c.L), K: gadgets.Dense(c.K),
	})
	ch.Bind(c.ComX, c.HS)
	ch.Finalize()
	rg.Bits(c.Eta, 8*hashes.SaltBytes)
	h, err := gadgets.DigestSecret(api, keyproof.LabelSlot, c.S, c.Eta)
	if err != nil {
		return err
	}
	api.AssertIsEqual(h, c.HS)
	return nil
}

// Assign returns the assignment for a slot's data ciphertext, with Com(x).
func Assign(cfg Config, p *rlwe.Params, ct *rlwe.Ciphertext, S []int64, rhoX []byte, s []int64, eta []byte, ew *rlwe.EncWitness) (*Circuit, error) {
	m := cfg.Class.M()
	if len(S) != m {
		return nil, fmt.Errorf("encproof: %d data entries, want %d", len(S), m)
	}
	c10, c11 := p.ToBig(ct.C0), p.ToBig(ct.C1)
	msg := make([]*big.Int, cfg.N)
	for i := range msg {
		msg[i] = new(big.Int)
	}
	for k, x := range S {
		msg[m-1-k].Mul(cfg.KEnc, big.NewInt(x))
	}
	L, K, err := gadgets.Quotients(cfg.N, cfg.Q, []gadgets.WTerm{{A: c11, B: gadgets.Ints(s)}},
		[][]*big.Int{c10}, [][]*big.Int{gadgets.Ints(ew.E), msg})
	if err != nil {
		return nil, fmt.Errorf("encproof: %w", err)
	}
	comX, err := cfg.Class.CommitX(hashes.BN254, S, rhoX)
	if err != nil {
		return nil, err
	}
	hs, err := hashes.DigSecret(hashes.BN254, keyproof.LabelSlot, s, eta)
	if err != nil {
		return nil, err
	}
	a := New(cfg)
	for i := 0; i < cfg.N; i++ {
		a.C10[i], a.C11[i], a.S[i], a.E[i], a.L[i], a.K[i] = c10[i], c11[i], s[i], ew.E[i], L[i], K[i]
	}
	for k, x := range S {
		a.X[k] = x
	}
	a.RhoX, a.ComX, a.HS, a.Eta = new(big.Int).SetBytes(rhoX), comX, hs, new(big.Int).SetBytes(eta)
	return a, nil
}

// PublicAssignment returns the public part of the statement: c1, Com(x)
// and h_s.
func PublicAssignment(cfg Config, p *rlwe.Params, c1 *rlwe.Ciphertext, comX, hs *big.Int) *Circuit {
	c := New(cfg)
	c10, c11 := p.ToBig(c1.C0), p.ToBig(c1.C1)
	for i := 0; i < cfg.N; i++ {
		c.C10[i], c.C11[i] = c10[i], c11[i]
	}
	c.ComX, c.HS = comX, hs
	return c
}
