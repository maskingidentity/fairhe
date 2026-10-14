package rlwe

import (
	"fmt"
	"io"
	"math/big"
)

// Case 1 seller path (paper Section 3.3): c' = c S_bar, c'' = Sanitize(c'),
// D = MS_qdel(Ext_J(c'')); buyer: Decode(D0 + (D1 s_B)_J).

// SanitizeWitness is the witness of the sanitisation: the encryption of zero
// (v, e0, e1) and the flood e_fl added to coefficient J of the first
// component, |e_fl| <= 2^sigma_fl.
type SanitizeWitness struct {
	ZeroEncWitness
	EFl *big.Int
}

// Sanitize returns the sanitised ciphertext (the paper's c double-prime)
// c_san = c' + (b v + e0, a v + e1) + (e_fl X^J, 0) under the buyer's public
// key. It must be the last operation on the evaluated ciphertext.
func (p *Params) Sanitize(pk *PublicKey, ct *Ciphertext, rng io.Reader) (*Ciphertext, *SanitizeWitness, error) {
	smp := p.newSampler(rng)
	z0, z1, zw, err := p.encZero(pk, smp)
	if err != nil {
		return nil, nil, err
	}
	efl, err := smp.flood(p.lit.SigmaFl)
	if err != nil {
		return nil, nil, err
	}
	c0 := p.Add(ct.C0, z0)
	p.AddToCoeff(c0, p.lit.J, efl)
	return &Ciphertext{C0: c0, C1: p.Add(ct.C1, z1)}, &SanitizeWitness{ZeroEncWitness: *zw, EFl: efl}, nil
}

// Deliverable is D = MS_qdel(Ext_J(c_san)) = (D0, D1): the released
// coefficient of the first component and the whole second component, all
// in [0, q_del) (N + 1 coefficients).
type Deliverable struct {
	D0 *big.Int
	D1 []*big.Int
}

// SwitchWitness holds, for the released coefficient and for every
// coefficient of the second component, the canonical value c in [0, Q)
// before the switch and the rounding remainder r = Q D~ - q_del c with
// D~ = round(q_del c / Q) in [0, q_del] and D = D~ mod q_del; |r| <= Q/2.
type SwitchWitness struct {
	C0J *big.Int
	C1  []*big.Int
	R0  *big.Int
	R1  []*big.Int
}

// ExtractSwitch returns D = MS_qdel(Ext_J(c_san)) and its rounding witness.
func (p *Params) ExtractSwitch(ct *Ciphertext) (*Deliverable, *SwitchWitness, error) {
	if p.lit.Case != Case1 {
		return nil, nil, fmt.Errorf("rlwe: ExtractSwitch is the Case 1 delivery")
	}
	c0J := p.coeffOf(ct.C0, p.lit.J)
	c1 := p.ToBig(ct.C1)
	d0, r0 := p.switchCoeff(c0J)
	d1 := make([]*big.Int, len(c1))
	r1 := make([]*big.Int, len(c1))
	for i, c := range c1 {
		d1[i], r1[i] = p.switchCoeff(c)
	}
	return &Deliverable{D0: d0, D1: d1}, &SwitchWitness{C0J: c0J, C1: c1, R0: r0, R1: r1}, nil
}

// switchCoeff returns D = round(q_del c / Q) mod q_del and r = Q D~ - q_del c
// for c in [0, Q).
func (p *Params) switchCoeff(c *big.Int) (*big.Int, *big.Int) {
	num := new(big.Int).Mul(p.lit.QDel, c)
	tilde := roundDiv(num, p.q)
	r := new(big.Int).Mul(p.q, tilde)
	r.Sub(r, num)
	return tilde.Mod(tilde, p.lit.QDel), r
}

// DecryptDeliverable returns the raw decryption of the released coefficient
// modulo q_del, x = D0 + (D1 s)_J in [0, q_del), computed as one negacyclic
// inner product over the integers.
func (p *Params) DecryptDeliverable(sk *SecretKey, d *Deliverable) *big.Int {
	x := new(big.Int).Set(d.D0)
	x.Add(x, negacyclicCoeffBig(d.D1, sk.S, p.lit.J))
	return x.Mod(x, p.lit.QDel)
}

// DecodeDeliverableBFV decodes the Case 1 BFV result, round(t x / q_del) mod t.
func (p *Params) DecodeDeliverableBFV(sk *SecretKey, d *Deliverable) *big.Int {
	return p.DecodeBFV(p.DecryptDeliverable(sk, d), p.lit.QDel)
}

// DecodeDeliverableCKKS decodes the Case 1 CKKS result, x / Delta' with
// Delta' = Delta q_del / Q.
func (p *Params) DecodeDeliverableCKKS(sk *SecretKey, d *Deliverable) *big.Rat {
	return p.DecodeCKKS(p.DecryptDeliverable(sk, d), p.lit.QDel)
}

// negacyclicCoeffBig returns coefficient j of a s modulo X^N + 1 over the
// integers for integer a and small s.
func negacyclicCoeffBig(a []*big.Int, s []int64, j int) *big.Int {
	N := len(a)
	acc := new(big.Int)
	t := new(big.Int)
	for i := 0; i < N; i++ {
		k := j - i
		sign := int64(1)
		if k < 0 {
			k += N
			sign = -1
		}
		sk := s[k] * sign
		switch sk {
		case 0:
		case 1:
			acc.Add(acc, a[i])
		case -1:
			acc.Sub(acc, a[i])
		default:
			acc.Add(acc, t.Mul(a[i], big.NewInt(sk)))
		}
	}
	return acc
}
