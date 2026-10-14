package rlwe

import (
	"fmt"
	"io"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/ring"
)

// SecretKey is a ternary secret s (coefficient domain).
type SecretKey struct {
	S []int64
}

// PublicKey is pk = (b, a) with b = -a s + e_pk.
type PublicKey struct {
	B, A ring.Poly
}

// KeyWitness is the witness of the key relation proven by pi_key:
// b = -a s + e_pk with ||s||_inf <= 1 and ||e_pk||_inf <= B_err.
type KeyWitness struct {
	S   []int64
	EPk []int64
}

// Ciphertext is (c0, c1) with raw decryption c0 + c1 s.
type Ciphertext struct {
	C0, C1 ring.Poly
}

// EncWitness is the fresh error e of a secret-key encryption.
type EncWitness struct {
	E []int64
}

// KeyGen samples a ternary secret and returns pk = (b, a) for the given
// uniform component a, normally a public coin (CoinPoly).
func (p *Params) KeyGen(a ring.Poly, rng io.Reader) (*SecretKey, *PublicKey, *KeyWitness, error) {
	smp := p.newSampler(rng)
	s, err := smp.ternary(p.N())
	if err != nil {
		return nil, nil, nil, err
	}
	e, err := smp.gaussian(p.N())
	if err != nil {
		return nil, nil, nil, err
	}
	b := p.Sub(p.FromSmall(e), p.MulSmall(a, s)) // b = e - a s
	return &SecretKey{S: s}, &PublicKey{B: b, A: p.Copy(a)}, &KeyWitness{S: s, EPk: e}, nil
}

// ScaleMessage returns the plaintext polynomial K_enc m of an integer
// message m (centred, at most N coefficients): Delta m for BFV and
// 2^(LogScaleEnc - FracBits) m for CKKS, whose message is in units of
// 2^-FracBits.
func (p *Params) ScaleMessage(m []int64) []*big.Int {
	k := p.EncScale()
	out := make([]*big.Int, p.N())
	for i := range out {
		out[i] = new(big.Int)
		if i < len(m) && m[i] != 0 {
			out[i].Mul(k, big.NewInt(m[i]))
		}
	}
	return out
}

// ScalePlain returns K_pt m, the plaintext operand of a product: m itself
// for BFV and m 2^(LogScalePt - FracBits) for CKKS.
func (p *Params) ScalePlain(m []int64) ([]int64, error) {
	k := p.PtScale()
	out := make([]int64, p.N())
	for i, x := range m {
		if k != 1 && (x > (1<<62)/k || x < -(1<<62)/k) {
			return nil, fmt.Errorf("rlwe: plaintext coefficient %d overflows at scale %d", x, k)
		}
		out[i] = x * k
	}
	return out, nil
}

// EncryptSK returns the secret-key encryption (K_enc m + e - a1 s, a1) of
// the integer message m under s, for a uniform a1: a public coin in Case 2,
// a fresh element (FreshUniform) in Case 1.
func (p *Params) EncryptSK(sk *SecretKey, m []int64, a1 ring.Poly, rng io.Reader) (*Ciphertext, *EncWitness, error) {
	if len(m) > p.N() {
		return nil, nil, fmt.Errorf("rlwe: message of %d coefficients", len(m))
	}
	e, err := p.newSampler(rng).gaussian(p.N())
	if err != nil {
		return nil, nil, err
	}
	c0 := p.FromBig(p.ScaleMessage(m))
	c0 = p.Add(c0, p.FromSmall(e))
	c0 = p.Sub(c0, p.MulSmall(a1, sk.S))
	return &Ciphertext{C0: c0, C1: p.Copy(a1)}, &EncWitness{E: e}, nil
}

// MulPlain returns (c0 pt, c1 pt) for the plaintext operand pt = K_pt m
// with centred integer coefficients: the single plaintext-ciphertext
// product of the running example.
func (p *Params) MulPlain(ct *Ciphertext, m []int64) (*Ciphertext, error) {
	pt, err := p.ScalePlain(m)
	if err != nil {
		return nil, err
	}
	ptQ := p.FromSmall(pt)
	return &Ciphertext{C0: p.Mul(ct.C0, ptQ), C1: p.Mul(ct.C1, ptQ)}, nil
}

// RawDecrypt returns the raw decryption c0 + c1 s in [0, Q).
func (p *Params) RawDecrypt(sk *SecretKey, ct *Ciphertext) []*big.Int {
	return p.ToBig(p.Add(ct.C0, p.MulSmall(ct.C1, sk.S)))
}

// encZero returns a fresh public-key encryption of zero, (b v + e0, a v + e1),
// with its witness: the re-randomiser of Sanitize (Case 1) and of the
// buyer's evaluation (Case 2).
func (p *Params) encZero(pk *PublicKey, smp *sampler) (ring.Poly, ring.Poly, *ZeroEncWitness, error) {
	v, err := smp.ternary(p.N())
	if err != nil {
		return ring.Poly{}, ring.Poly{}, nil, err
	}
	e0, err := smp.gaussian(p.N())
	if err != nil {
		return ring.Poly{}, ring.Poly{}, nil, err
	}
	e1, err := smp.gaussian(p.N())
	if err != nil {
		return ring.Poly{}, ring.Poly{}, nil, err
	}
	vQ := p.FromSmall(v)
	z0 := p.Add(p.Mul(pk.B, vQ), p.FromSmall(e0))
	z1 := p.Add(p.Mul(pk.A, vQ), p.FromSmall(e1))
	return z0, z1, &ZeroEncWitness{V: v, E0: e0, E1: e1}, nil
}

// ZeroEncWitness is the witness (v, e0, e1) of a public-key encryption of
// zero: ||v||_inf <= 1, ||e0||_inf, ||e1||_inf <= B_err.
type ZeroEncWitness struct {
	V, E0, E1 []int64
}
