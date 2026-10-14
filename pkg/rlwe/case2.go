package rlwe

import (
	"fmt"
	"io"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/ring"
)

// Case 2 path (paper Section 3.4): the seller registers c1 = Enc_S(x) under a
// slot key with public-coin uniform components; the buyer computes
// c2 = w_hat c1 + (b v + e0', a v + e1'), keeps c2,0 and orders with c2,1;
// the seller releases p = (c2,1 s)_J + e_fl; the buyer decodes
// (c2,0)_J + p.

// EvalRerand is the buyer's evaluation: the plaintext product by its
// operand m followed by a public-key encryption of zero under the slot key.
// The witness (v, e0', e1') bounds the re-randomisation that pi_eval fixes;
// e0' stays with the buyer and is not part of the relation.
func (p *Params) EvalRerand(pk *PublicKey, c1 *Ciphertext, m []int64, rng io.Reader) (*Ciphertext, *ZeroEncWitness, error) {
	if p.lit.Case != Case2 {
		return nil, nil, fmt.Errorf("rlwe: EvalRerand is the Case 2 evaluation")
	}
	prod, err := p.MulPlain(c1, m)
	if err != nil {
		return nil, nil, err
	}
	z0, z1, zw, err := p.encZero(pk, p.newSampler(rng))
	if err != nil {
		return nil, nil, err
	}
	return &Ciphertext{C0: p.Add(prod.C0, z0), C1: p.Add(prod.C1, z1)}, zw, nil
}

// PartialDecrypt returns the seller's flooded partial decryption of the
// released coefficient, p = (c2,1 s)_J + e_fl mod Q, and the flood e_fl.
// It is a single negacyclic inner product (no NTT).
func (p *Params) PartialDecrypt(sk *SecretKey, c21 ring.Poly, rng io.Reader) (*big.Int, *big.Int, error) {
	if p.lit.Case != Case2 {
		return nil, nil, fmt.Errorf("rlwe: PartialDecrypt is the Case 2 delivery")
	}
	efl, err := p.newSampler(rng).flood(p.lit.SigmaFl)
	if err != nil {
		return nil, nil, err
	}
	pd := p.ProductCoeff(c21, sk.S, p.lit.J)
	pd.Add(pd, efl)
	return pd.Mod(pd, p.q), efl, nil
}

// Recover returns the buyer's raw decryption of the released coefficient,
// x = (c2,0)_J + p mod Q.
func (p *Params) Recover(c20 ring.Poly, pd *big.Int) *big.Int {
	x := p.coeffOf(c20, p.lit.J)
	x.Add(x, pd)
	return x.Mod(x, p.q)
}
