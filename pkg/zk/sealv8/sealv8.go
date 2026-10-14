// Package sealv8 is the sealing of the settlement variant for chains that
// cannot verify proofs (option O1, paper
// Appendix B). The seller seals the deliverable's field elements m (the
// packed D of Case 1, or p of Case 2) with a fresh salt eta_D under a key
// derived from its adaptor witness k, and proves pi_seal:
//
//	Y = k G on secp256k1,  kappa = H_dig("seal.kdf", 64-bit limbs of k),
//	c_j = m_j + H_dig("seal.ks", kappa, j)  (addition in the circuit field),
//	h_D = H_dig("h_D.seal", m || eta_D),     h_c = H_dig("h_cD", c),
//
// with the order ID, Y, h_D and h_c public. The deliverable's correctness
// proof refers to m through the same salted h_D, and anyone who learns k
// opens c. Case 1 seals over BLS12-381 (the field of pi_eval), Case 2 over
// BN254 (the field of pi_dec).
package sealv8

import (
	"fmt"
	"math/big"

	"fairhe/pkg/hashes"
	"fairhe/pkg/zk/gadgets"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/multicommit"
)

// Labels of the variant's digests.
const (
	LabelKDF = "seal.kdf"
	LabelKS  = "seal.ks"
	LabelHD  = "h_D.seal"
	LabelHC  = "h_cD"
)

// SaltBits is the width of eta_D.
const SaltBits = 8 * hashes.SaltBytes

// limbs returns the four 64-bit little-endian limbs of a secp256k1 scalar,
// as gnark's emulated Secp256k1Fr holds a reduced element.
func limbs(k *big.Int) []*big.Int {
	mask := new(big.Int).SetUint64(^uint64(0))
	out := make([]*big.Int, 4)
	for i := range out {
		out[i] = new(big.Int).And(new(big.Int).Rsh(k, uint(64*i)), mask)
	}
	return out
}

// Kappa derives the sealing key from the adaptor witness k (0 <= k < n).
func Kappa(f hashes.Field, k *big.Int) (*big.Int, error) {
	return hashes.Dig(f, LabelKDF, limbs(k))
}

func keystream(f hashes.Field, kappa *big.Int, j int) (*big.Int, error) {
	return hashes.Dig(f, LabelKS, []*big.Int{kappa, big.NewInt(int64(j))})
}

// Seal returns c_j = m_j + keystream_j(kappa(k)).
func Seal(f hashes.Field, k *big.Int, m []*big.Int) ([]*big.Int, error) {
	return stream(f, k, m, 1)
}

// Unseal returns m_j = c_j - keystream_j(kappa(k)).
func Unseal(f hashes.Field, k *big.Int, c []*big.Int) ([]*big.Int, error) {
	return stream(f, k, c, -1)
}

func stream(f hashes.Field, k *big.Int, in []*big.Int, sign int64) ([]*big.Int, error) {
	kappa, err := Kappa(f, k)
	if err != nil {
		return nil, err
	}
	mod := f.Modulus()
	out := make([]*big.Int, len(in))
	for j, v := range in {
		ks, err := keystream(f, kappa, j)
		if err != nil {
			return nil, err
		}
		out[j] = new(big.Int).Mod(new(big.Int).Add(v, new(big.Int).Mul(big.NewInt(sign), ks)), mod)
	}
	return out, nil
}

// HD returns the salted digest h_D of the deliverable's elements.
func HD(f hashes.Field, m []*big.Int, eta []byte) (*big.Int, error) {
	if len(eta) != hashes.SaltBytes {
		return nil, fmt.Errorf("sealv8: salt of %d bytes", len(eta))
	}
	return hashes.Dig(f, LabelHD, append(append([]*big.Int{}, m...), new(big.Int).SetBytes(eta)))
}

// HC returns the digest of the sealed elements.
func HC(f hashes.Field, c []*big.Int) (*big.Int, error) { return hashes.Dig(f, LabelHC, c) }

// Circuit is pi_seal for n sealed elements.
type Circuit struct {
	OrderID frontend.Variable                             `gnark:",public"`
	Y       sw_emulated.AffinePoint[emulated.Secp256k1Fp] `gnark:",public"`
	HD      frontend.Variable                             `gnark:",public"`
	HC      frontend.Variable                             `gnark:",public"`

	K   emulated.Element[emulated.Secp256k1Fr]
	M   []frontend.Variable
	Eta frontend.Variable
}

// New returns an empty circuit sealing n elements.
func New(n int) *Circuit { return &Circuit{M: make([]frontend.Variable, n)} }

// Define implements the relation.
func (c *Circuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.Secp256k1Fp, emulated.Secp256k1Fr](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		return err
	}
	curve.AssertIsEqual(curve.ScalarMulBase(&c.K), &c.Y)
	fr, err := emulated.NewField[emulated.Secp256k1Fr](api)
	if err != nil {
		return err
	}
	k := fr.ReduceStrict(&c.K) // canonical limbs: kappa is a function of the k of Y
	kappa, err := gadgets.Digest(api, LabelKDF, k.Limbs)
	if err != nil {
		return err
	}
	sealed := make([]frontend.Variable, len(c.M))
	for j, m := range c.M {
		ks, err := gadgets.Digest(api, LabelKS, []frontend.Variable{kappa, j})
		if err != nil {
			return err
		}
		sealed[j] = api.Add(m, ks)
	}
	hc, err := gadgets.Digest(api, LabelHC, sealed)
	if err != nil {
		return err
	}
	api.AssertIsEqual(hc, c.HC)
	rg := gadgets.NewRanger(api)
	rg.Bits(c.Eta, SaltBits)
	hd, err := gadgets.Digest(api, LabelHD, append(append([]frontend.Variable{}, c.M...), c.Eta))
	if err != nil {
		return err
	}
	api.AssertIsEqual(hd, c.HD)
	// Bind the order ID (and the digests) into the commitment.
	multicommit.WithCommitment(api, func(frontend.API, frontend.Variable) error { return nil }, c.OrderID, c.HD, c.HC)
	return nil
}

// Public holds the public inputs of a seal.
type Public struct {
	OrderID, HD, HC *big.Int
	Yx, Yy          *big.Int
	C               []*big.Int // the sealed elements, published with the proof
}

// Assign seals m under k and returns the assignment and the public values;
// Y = k G is the adaptor statement (Yx, Yy).
func Assign(f hashes.Field, orderID, k, yx, yy *big.Int, m []*big.Int, eta []byte) (*Circuit, *Public, error) {
	c, err := Seal(f, k, m)
	if err != nil {
		return nil, nil, err
	}
	hd, err := HD(f, m, eta)
	if err != nil {
		return nil, nil, err
	}
	hc, err := HC(f, c)
	if err != nil {
		return nil, nil, err
	}
	a := New(len(m))
	a.OrderID, a.HD, a.HC = orderID, hd, hc
	a.Y = sw_emulated.AffinePoint[emulated.Secp256k1Fp]{X: emulated.ValueOf[emulated.Secp256k1Fp](yx), Y: emulated.ValueOf[emulated.Secp256k1Fp](yy)}
	a.K = emulated.ValueOf[emulated.Secp256k1Fr](k)
	for j, v := range m {
		a.M[j] = v
	}
	a.Eta = new(big.Int).SetBytes(eta)
	return a, &Public{OrderID: orderID, HD: hd, HC: hc, Yx: yx, Yy: yy, C: c}, nil
}

// PublicAssignment is the verifier's view: the order ID, Y and the digests.
func PublicAssignment(n int, pub *Public) *Circuit {
	a := New(n)
	a.OrderID, a.HD, a.HC = pub.OrderID, pub.HD, pub.HC
	a.Y = sw_emulated.AffinePoint[emulated.Secp256k1Fp]{X: emulated.ValueOf[emulated.Secp256k1Fp](pub.Yx), Y: emulated.ValueOf[emulated.Secp256k1Fp](pub.Yy)}
	return a
}

// CurveOf returns the proof system's curve of a field.
func CurveOf(f hashes.Field) ecc.ID {
	if f == hashes.BN254 {
		return ecc.BN254
	}
	return ecc.BLS12_381
}
