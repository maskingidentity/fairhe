// Package decproof is the Case 2 decryption proof pi_dec,
// proven by the seller with its claim and verified by the settlement
// contract over BN254: the released value is the flooded partial decryption
// of the ordered c2,1 under the slot secret,
//
//	p = (c2,1 s)_J + e_fl mod Q,  |e_fl| <= 2^sigma_fl (closed interval),
//	h_s = H_dig(s || eta_s),  h_c21 = H_dig(c2,1),
//
// for the order ID, h_c21 and h_s that the contract recorded (paper Section
// 3.4). The proof does no decoding and no rounding; the salted digest h_s
// binds the secret to the slot's registered key.
package decproof

import (
	"fmt"
	"math/big"

	"fairhe/pkg/hashes"
	"fairhe/pkg/rlwe"
	"fairhe/pkg/zk/gadgets"
	"fairhe/pkg/zk/keyproof"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/multicommit"
)

// LabelHC21 is the digest label of the ordered c2,1.
const LabelHC21 = "h_c21"

// Config fixes the constants of one verification key.
type Config struct {
	N, J    int
	Q       *big.Int
	QBits   int // bit length of Q - 1: digest packing of c2,1
	SigmaFl int
}

// ConfigFor returns the configuration of a Case 2 parameter set.
func ConfigFor(p *rlwe.Params) (Config, error) {
	if p.Case() != rlwe.Case2 {
		return Config{}, fmt.Errorf("decproof: parameters of case %d", p.Case())
	}
	q := p.Q()
	return Config{N: p.N(), J: p.J(), Q: q, QBits: new(big.Int).Sub(q, big.NewInt(1)).BitLen(), SigmaFl: p.SigmaFl()}, nil
}

// Circuit is pi_dec.
type Circuit struct {
	OrderID frontend.Variable `gnark:",public"`
	HC21    frontend.Variable `gnark:",public"`
	HS      frontend.Variable `gnark:",public"`
	P       frontend.Variable `gnark:",public"`

	C21 []frontend.Variable
	S   []frontend.Variable
	Eta frontend.Variable
	EFl frontend.Variable
	Ell frontend.Variable // quotient by Q

	cfg Config
}

// New returns an empty circuit of the configuration.
func New(cfg Config) *Circuit {
	return &Circuit{C21: make([]frontend.Variable, cfg.N), S: make([]frontend.Variable, cfg.N), cfg: cfg}
}

// Define implements the relation.
func (c *Circuit) Define(api frontend.API) error {
	cfg := c.cfg
	if len(c.C21) != cfg.N {
		return fmt.Errorf("decproof: circuit shape does not match the configuration")
	}
	rg := gadgets.NewRanger(api)
	hc, err := gadgets.DigestPoly(api, rg, LabelHC21, c.C21, cfg.QBits)
	if err != nil {
		return err
	}
	api.AssertIsEqual(hc, c.HC21)
	for _, s := range c.S {
		gadgets.Ternary(api, s)
	}
	rg.Bits(c.Eta, 8*hashes.SaltBytes)
	hs, err := gadgets.DigestSecret(api, keyproof.LabelSlot, c.S, c.Eta)
	if err != nil {
		return err
	}
	api.AssertIsEqual(hs, c.HS)
	// p = (c2,1 s)_J + e_fl - Q ell with p canonical; |(c2,1 s)_J| is below
	// N 2^QBits < 2N Q, so |ell| <= 2N + 2.
	inner := gadgets.NegacyclicCoeff(api, c.C21, c.S, cfg.J)
	rg.InSym(c.EFl, new(big.Int).Lsh(big.NewInt(1), uint(cfg.SigmaFl)))
	rg.InSym(c.Ell, big.NewInt(int64(2*cfg.N+2)))
	rg.Canonical(c.P, cfg.Q)
	api.AssertIsEqual(api.Add(inner, c.EFl), api.Add(c.P, api.Mul(c.Ell, cfg.Q)))
	// Bind the order ID (and the other public inputs) into the commitment.
	multicommit.WithCommitment(api, func(frontend.API, frontend.Variable) error { return nil },
		c.OrderID, c.HC21, c.HS, c.P)
	return nil
}

// Public holds the public inputs as the contract records them.
type Public struct {
	OrderID, HC21, HS, P *big.Int
}

// DigestC21 returns h_c21 natively, as the buyer records it with its order.
func DigestC21(cfg Config, c21 []*big.Int) (*big.Int, error) {
	return hashes.DigPoly(hashes.BN254, LabelHC21, c21, cfg.QBits)
}

// Assign returns the assignment for a claim: the ordered c2,1, the slot's
// secret and salt, the released p and its flood.
func Assign(cfg Config, orderID *big.Int, c21 []*big.Int, s []int64, eta []byte, p, efl *big.Int) (*Circuit, *Public, error) {
	hc, err := DigestC21(cfg, c21)
	if err != nil {
		return nil, nil, err
	}
	hs, err := hashes.DigSecret(hashes.BN254, keyproof.LabelSlot, s, eta)
	if err != nil {
		return nil, nil, err
	}
	inner := new(big.Int)
	t := new(big.Int)
	for i := 0; i < cfg.N; i++ {
		k, sign := cfg.J-i, int64(1)
		if k < 0 {
			k, sign = k+cfg.N, -1
		}
		if s[k] != 0 {
			inner.Add(inner, t.Mul(c21[i], big.NewInt(sign*s[k])))
		}
	}
	num := new(big.Int).Add(inner, efl)
	num.Sub(num, p)
	ell, rem := new(big.Int).QuoRem(num, cfg.Q, new(big.Int))
	if rem.Sign() != 0 {
		return nil, nil, fmt.Errorf("decproof: p is not the partial decryption")
	}
	a := New(cfg)
	for i := 0; i < cfg.N; i++ {
		a.C21[i], a.S[i] = c21[i], s[i]
	}
	a.OrderID, a.HC21, a.HS, a.P = orderID, hc, hs, p
	a.Eta, a.EFl, a.Ell = new(big.Int).SetBytes(eta), efl, ell
	return a, &Public{OrderID: orderID, HC21: hc, HS: hs, P: p}, nil
}
