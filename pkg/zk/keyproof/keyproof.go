// Package keyproof is pi_key: a public key pk = (b, a) is
// well formed for one short secret,
//
//	b = -a s + e_pk,  ||s||_inf <= 1,  ||e_pk||_inf <= B_err,
//	h = H_dig(s || eta),
//
// with the salted digest h that the other proofs about the same secret open
// (h_sB for the Case 1 buyer key over BLS12-381, h_s for a Case 2 slot key
// over BN254). The verifier is the counterparty, off-chain, so the key is a
// public input as polynomials.
package keyproof

import (
	"fmt"
	"math/big"

	"fairhe/pkg/hashes"
	"fairhe/pkg/rlwe"
	"fairhe/pkg/zk/gadgets"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

// Labels of the salted secret digests.
const (
	LabelBuyer = "h_sB" // Case 1 buyer key (BLS12-381)
	LabelSlot  = "h_s"  // Case 2 slot key (BN254), rlwe.LabelHS
)

// Config fixes the constants of one verification key.
type Config struct {
	N     int
	Q     *big.Int
	BErr  int64
	Label string
	Curve ecc.ID
}

// ConfigFor returns the configuration of a parameter set: the buyer key of
// Case 1 over BLS12-381, a slot key of Case 2 over BN254.
func ConfigFor(p *rlwe.Params) Config {
	cfg := Config{N: p.N(), Q: p.Q(), BErr: int64(p.BErr()), Label: LabelSlot, Curve: ecc.BN254}
	if p.Case() == rlwe.Case1 {
		cfg.Label, cfg.Curve = LabelBuyer, ecc.BLS12_381
	}
	return cfg
}

// Field returns the digest field of the configuration.
func (cfg Config) Field() hashes.Field {
	if cfg.Curve == ecc.BLS12_381 {
		return hashes.BLS12381
	}
	return hashes.BN254
}

// Circuit is pi_key.
type Circuit struct {
	A, B []frontend.Variable `gnark:",public"`
	H    frontend.Variable   `gnark:",public"`

	S, E []frontend.Variable
	Eta  frontend.Variable
	L, K []frontend.Variable

	cfg Config
}

// New returns an empty circuit of the configuration.
func New(cfg Config) *Circuit {
	mk := func() []frontend.Variable { return make([]frontend.Variable, cfg.N) }
	return &Circuit{A: mk(), B: mk(), S: mk(), E: mk(), L: mk(), K: mk(), cfg: cfg}
}

// Define implements the relation.
func (c *Circuit) Define(api frontend.API) error {
	cfg := c.cfg
	if len(c.A) != cfg.N {
		return fmt.Errorf("keyproof: circuit shape does not match the configuration")
	}
	rg := gadgets.NewRanger(api)
	berr := big.NewInt(cfg.BErr)
	lb := big.NewInt(int64(cfg.N + 2))
	for i := 0; i < cfg.N; i++ {
		gadgets.Ternary(api, c.S[i])
		rg.InSym(c.E[i], berr)
		rg.InSym(c.L[i], lb)
	}
	// a s + b - e = Q L + (X^N + 1) K
	ch := gadgets.NewChecker(api, cfg.N)
	ch.Add(gadgets.Identity{
		Products: []gadgets.Term{{A: gadgets.Dense(c.A), B: gadgets.Dense(c.S)}},
		Add:      []gadgets.Poly{gadgets.Dense(c.B)},
		Sub:      []gadgets.Poly{gadgets.Dense(c.E)},
		Q:        cfg.Q, L: gadgets.Dense(c.L), K: gadgets.Dense(c.K),
	})
	ch.Bind(c.H)
	ch.Finalize()
	rg.Bits(c.Eta, 8*hashes.SaltBytes)
	h, err := gadgets.DigestSecret(api, cfg.Label, c.S, c.Eta)
	if err != nil {
		return err
	}
	api.AssertIsEqual(h, c.H)
	return nil
}

// Assign returns the assignment for a key, its witness and the salt, and
// the digest h.
func Assign(cfg Config, p *rlwe.Params, pk *rlwe.PublicKey, w *rlwe.KeyWitness, eta []byte) (*Circuit, *big.Int, error) {
	a, b := p.ToBig(pk.A), p.ToBig(pk.B)
	L, K, err := gadgets.Quotients(cfg.N, cfg.Q,
		[]gadgets.WTerm{{A: a, B: gadgets.Ints(w.S)}}, [][]*big.Int{b}, [][]*big.Int{gadgets.Ints(w.EPk)})
	if err != nil {
		return nil, nil, fmt.Errorf("keyproof: %w", err)
	}
	h, err := hashes.DigSecret(cfg.Field(), cfg.Label, w.S, eta)
	if err != nil {
		return nil, nil, err
	}
	c := New(cfg)
	for i := 0; i < cfg.N; i++ {
		c.A[i], c.B[i], c.S[i], c.E[i], c.L[i], c.K[i] = a[i], b[i], w.S[i], w.EPk[i], L[i], K[i]
	}
	c.H, c.Eta = h, new(big.Int).SetBytes(eta)
	return c, h, nil
}

// PublicAssignment returns the public part of the statement for a key and
// its digest, for the counterparty's verification.
func PublicAssignment(cfg Config, p *rlwe.Params, pk *rlwe.PublicKey, h *big.Int) *Circuit {
	c := New(cfg)
	a, b := p.ToBig(pk.A), p.ToBig(pk.B)
	for i := 0; i < cfg.N; i++ {
		c.A[i], c.B[i] = a[i], b[i]
	}
	c.H = h
	return c
}
