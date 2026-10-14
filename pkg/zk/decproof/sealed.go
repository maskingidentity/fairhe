package decproof

import (
	"fmt"
	"math/big"

	"fairhe/pkg/hashes"
	"fairhe/pkg/zk/gadgets"
	"fairhe/pkg/zk/keyproof"
	"fairhe/pkg/zk/sealv8"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/multicommit"
)

// SealedCircuit is pi_dec for the settlement variant without on-chain proof
// verification (option O1, paper Appendix B): the same relation as Circuit,
// with the released p kept secret behind the salted digest
// h_D = H_dig(p || eta_D) that pi_seal shares. It is a separate type so that
// the main circuit and its verification key stay unchanged.
type SealedCircuit struct {
	OrderID frontend.Variable `gnark:",public"`
	HC21    frontend.Variable `gnark:",public"`
	HS      frontend.Variable `gnark:",public"`
	HD      frontend.Variable `gnark:",public"`

	C21  []frontend.Variable
	S    []frontend.Variable
	Eta  frontend.Variable
	EFl  frontend.Variable
	Ell  frontend.Variable
	P    frontend.Variable
	EtaD frontend.Variable

	cfg Config
}

// NewSealed returns an empty sealed circuit of the configuration.
func NewSealed(cfg Config) *SealedCircuit {
	return &SealedCircuit{C21: make([]frontend.Variable, cfg.N), S: make([]frontend.Variable, cfg.N), cfg: cfg}
}

// Define implements the relation of Circuit with p behind h_D.
func (c *SealedCircuit) Define(api frontend.API) error {
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
	inner := gadgets.NegacyclicCoeff(api, c.C21, c.S, cfg.J)
	rg.InSym(c.EFl, new(big.Int).Lsh(big.NewInt(1), uint(cfg.SigmaFl)))
	rg.InSym(c.Ell, big.NewInt(int64(2*cfg.N+2)))
	rg.Canonical(c.P, cfg.Q)
	api.AssertIsEqual(api.Add(inner, c.EFl), api.Add(c.P, api.Mul(c.Ell, cfg.Q)))
	rg.Bits(c.EtaD, sealv8.SaltBits)
	hd, err := gadgets.Digest(api, sealv8.LabelHD, []frontend.Variable{c.P, c.EtaD})
	if err != nil {
		return err
	}
	api.AssertIsEqual(hd, c.HD)
	multicommit.WithCommitment(api, func(frontend.API, frontend.Variable) error { return nil },
		c.OrderID, c.HC21, c.HS, c.HD)
	return nil
}

// SealedPublic holds the public inputs of a sealed claim.
type SealedPublic struct {
	OrderID, HC21, HS, HD *big.Int
}

// AssignSealed returns the sealed assignment: the claim's witness of Assign
// with p hidden behind h_D = H_dig(p || etaD).
func AssignSealed(cfg Config, orderID *big.Int, c21 []*big.Int, s []int64, eta []byte, p, efl *big.Int, etaD []byte) (*SealedCircuit, *SealedPublic, error) {
	plain, pub, err := Assign(cfg, orderID, c21, s, eta, p, efl)
	if err != nil {
		return nil, nil, err
	}
	hd, err := sealv8.HD(hashes.BN254, []*big.Int{p}, etaD)
	if err != nil {
		return nil, nil, err
	}
	a := NewSealed(cfg)
	copy(a.C21, plain.C21)
	copy(a.S, plain.S)
	a.OrderID, a.HC21, a.HS, a.HD = orderID, pub.HC21, pub.HS, hd
	a.Eta, a.EFl, a.Ell, a.P = plain.Eta, plain.EFl, plain.Ell, p
	a.EtaD = new(big.Int).SetBytes(etaD)
	return a, &SealedPublic{OrderID: orderID, HC21: pub.HC21, HS: pub.HS, HD: hd}, nil
}

// SealedPublicAssignment is the verifier's view of a sealed claim.
func SealedPublicAssignment(cfg Config, pub *SealedPublic) *SealedCircuit {
	a := NewSealed(cfg)
	a.OrderID, a.HC21, a.HS, a.HD = pub.OrderID, pub.HC21, pub.HS, pub.HD
	return a
}
