package evalc1

import (
	"fmt"
	"math/big"

	"fairhe/pkg/hashes"
	"fairhe/pkg/zk/gadgets"
	"fairhe/pkg/zk/sealv8"

	"github.com/consensys/gnark/frontend"
)

// SealedCircuit is the Case 1 pi_eval of the settlement variant without
// on-chain proof verification (option O1, paper Appendix B): the relation
// of Circuit up to the switch to q_del, with D kept secret behind the salted
// digest h_D = H_dig(pack(D) || eta_D) that pi_seal shares, and no blob
// evaluation (the variant carries the sealed D, not a blob). It is a
// separate type so that the main circuit and its verification key stay
// unchanged.
type SealedCircuit struct {
	OrderID frontend.Variable `gnark:",public"`
	HC      frontend.Variable `gnark:",public"`
	HPk     frontend.Variable `gnark:",public"`
	ComX    frontend.Variable `gnark:",public"`
	HD      frontend.Variable `gnark:",public"`

	C0, C1, B, A []frontend.Variable
	X            []frontend.Variable
	Rho          frontend.Variable
	V, E0, E1    []frontend.Variable
	EFl          frontend.Variable
	CS1          []frontend.Variable
	CS0J         frontend.Variable
	Ell0         frontend.Variable
	L, K         []frontend.Variable
	D, W, R      []frontend.Variable
	EtaD         frontend.Variable

	cfg Config
}

// NewSealed returns an empty sealed circuit of the configuration.
func NewSealed(cfg Config) *SealedCircuit {
	n := cfg.N
	mk := func(k int) []frontend.Variable { return make([]frontend.Variable, k) }
	return &SealedCircuit{
		C0: mk(n), C1: mk(n), B: mk(n), A: mk(n), X: mk(cfg.M),
		V: mk(n), E0: mk(n), E1: mk(n), CS1: mk(n), L: mk(n), K: mk(n),
		D: mk(n + 1), W: mk(n + 1), R: mk(n + 1), cfg: cfg,
	}
}

// Define implements the relation of Circuit with h_D salted and no blob.
func (c *SealedCircuit) Define(api frontend.API) error {
	cfg := c.cfg
	n := cfg.N
	if len(c.C0) != n || len(c.X) != cfg.M || len(c.D) != n+1 {
		return fmt.Errorf("evalc1: circuit shape does not match the configuration")
	}
	rg := gadgets.NewRanger(api)
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
	for _, x := range c.X {
		rg.Entry(x, cfg.XBits, cfg.XMax)
	}
	rg.Bits(c.Rho, 128)
	com, err := gadgets.Commitment(api, LabelX, c.X, cfg.XBits, c.Rho)
	if err != nil {
		return err
	}
	api.AssertIsEqual(com, c.ComX)
	berr := big.NewInt(cfg.BErr)
	for i := 0; i < n; i++ {
		gadgets.Ternary(api, c.V[i])
		rg.InSym(c.E0[i], berr)
		rg.InSym(c.E1[i], berr)
	}
	rg.InSym(c.EFl, new(big.Int).Lsh(big.NewInt(1), uint(cfg.SigmaFl)))
	sbar := make([]frontend.Variable, cfg.M)
	support := make([]int, cfg.M)
	for k, x := range c.X {
		sbar[k] = api.Mul(x, cfg.PtScale)
		support[k] = cfg.M - 1 - k
	}
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
	ch.Bind(c.OrderID, c.HC, c.HPk, c.ComX, c.HD)
	ch.Finalize()
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
	// The deliverable behind the salted digest that pi_seal shares.
	elems := gadgets.Pack(api, c.D, cfg.DBits, cfg.DPer)
	rg.Bits(c.EtaD, sealv8.SaltBits)
	hd, err := gadgets.Digest(api, sealv8.LabelHD, append(elems, c.EtaD))
	if err != nil {
		return err
	}
	api.AssertIsEqual(hd, c.HD)
	return nil
}

// SealedPublic holds the public inputs of a sealed Case 1 claim.
type SealedPublic struct {
	OrderID, HC, HPk, ComX, HD *big.Int
	Elems                      []*big.Int // the packed D that pi_seal seals
}

// AssignSealed returns the sealed assignment for the inputs of a claim (Z
// is ignored) with the salt etaD of h_D.
func AssignSealed(cfg Config, in *Inputs, etaD []byte) (*SealedCircuit, *SealedPublic, error) {
	in2 := *in
	if in2.Z == nil {
		in2.Z = big.NewInt(1) // Assign evaluates the blob at Z; the sealed circuit ignores it
	}
	plain, pub, err := Assign(cfg, &in2)
	if err != nil {
		return nil, nil, err
	}
	hd, err := sealv8.HD(hashes.BLS12381, pub.Elems, etaD)
	if err != nil {
		return nil, nil, err
	}
	a := NewSealed(cfg)
	a.OrderID, a.HC, a.HPk, a.ComX, a.HD = pub.OrderID, pub.HC, pub.HPk, pub.ComX, hd
	copy(a.C0, plain.C0)
	copy(a.C1, plain.C1)
	copy(a.B, plain.B)
	copy(a.A, plain.A)
	copy(a.X, plain.X)
	a.Rho = plain.Rho
	copy(a.V, plain.V)
	copy(a.E0, plain.E0)
	copy(a.E1, plain.E1)
	a.EFl = plain.EFl
	copy(a.CS1, plain.CS1)
	a.CS0J, a.Ell0 = plain.CS0J, plain.Ell0
	copy(a.L, plain.L)
	copy(a.K, plain.K)
	copy(a.D, plain.D)
	copy(a.W, plain.W)
	copy(a.R, plain.R)
	a.EtaD = new(big.Int).SetBytes(etaD)
	return a, &SealedPublic{OrderID: pub.OrderID, HC: pub.HC, HPk: pub.HPk, ComX: pub.ComX, HD: hd, Elems: pub.Elems}, nil
}

// SealedPublicAssignment is the verifier's view of a sealed claim.
func SealedPublicAssignment(cfg Config, pub *SealedPublic) *SealedCircuit {
	a := NewSealed(cfg)
	a.OrderID, a.HC, a.HPk, a.ComX, a.HD = pub.OrderID, pub.HC, pub.HPk, pub.ComX, pub.HD
	return a
}
