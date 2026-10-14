package rlwe

import (
	"fmt"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/ring"
)

// Relation checkers: plain-Go re-verification of every
// relation that a circuit proves, from the exported
// witnesses. Products are recomputed by schoolbook negacyclic multiplication
// per RNS limb, independent of the NTT path that produced the values, and
// every bound is checked exactly.

// refMulSmall returns a * s in R_Q by schoolbook multiplication, skipping
// the zero coefficients of the small polynomial s.
func (p *Params) refMulSmall(a ring.Poly, s []int64) ring.Poly {
	N := p.N()
	out := p.ringQ.NewPoly()
	for li, qi := range p.lit.Q {
		ai, oi := a.Coeffs[li], out.Coeffs[li]
		for k, sk := range s {
			if sk == 0 {
				continue
			}
			neg := sk < 0
			mag := uint64(sk)
			if neg {
				mag = uint64(-sk)
			}
			mag %= qi
			for i := 0; i < N; i++ {
				idx, flip := i+k, false
				if idx >= N {
					idx -= N
					flip = true
				}
				term := ai[i]
				if mag != 1 {
					term = mulMod(term, mag, qi)
				}
				if neg != flip {
					oi[idx] = subMod(oi[idx], term, qi)
				} else {
					oi[idx] = addMod(oi[idx], term, qi)
				}
			}
		}
	}
	return out
}

func (p *Params) equal(a, b ring.Poly) bool { return p.ringQ.Equal(a, b) }

func checkTernary(name string, v []int64, n int) error {
	if len(v) != n {
		return fmt.Errorf("%s has %d coefficients, want %d", name, len(v), n)
	}
	for i, x := range v {
		if x < -1 || x > 1 {
			return fmt.Errorf("%s[%d] = %d is not ternary", name, i, x)
		}
	}
	return nil
}

func checkBounded(name string, v []int64, n int, b int64) error {
	if len(v) != n {
		return fmt.Errorf("%s has %d coefficients, want %d", name, len(v), n)
	}
	for i, x := range v {
		if x < -b || x > b {
			return fmt.Errorf("%s[%d] = %d outside [-%d, %d]", name, i, x, b, b)
		}
	}
	return nil
}

// checkFlood checks |e_fl| <= 2^sigma_fl (the closed interval).
func (p *Params) checkFlood(efl *big.Int) error {
	bound := new(big.Int).Lsh(big.NewInt(1), uint(p.lit.SigmaFl))
	if new(big.Int).Abs(efl).Cmp(bound) > 0 {
		return fmt.Errorf("flood %s outside [-2^%d, 2^%d]", efl, p.lit.SigmaFl, p.lit.SigmaFl)
	}
	return nil
}

// CheckKey verifies the relation of pi_key: b = -a s + e_pk with s ternary
// and ||e_pk||_inf <= B_err.
func (p *Params) CheckKey(pk *PublicKey, w *KeyWitness) error {
	N, berr := p.N(), int64(p.lit.BErr)
	if err := checkTernary("s", w.S, N); err != nil {
		return fmt.Errorf("pi_key: %w", err)
	}
	if err := checkBounded("e_pk", w.EPk, N, berr); err != nil {
		return fmt.Errorf("pi_key: %w", err)
	}
	want := p.Sub(p.FromSmall(w.EPk), p.refMulSmall(pk.A, w.S))
	if !p.equal(want, pk.B) {
		return fmt.Errorf("pi_key: b != -a s + e_pk")
	}
	return nil
}

// CheckEnc verifies the encryption relation of pi_member (Case 1) and pi_enc
// (Case 2): c0 = K_enc m + e - c1 s with s ternary and ||e||_inf <= B_err,
// that is, the raw decryption of c is K_enc m + e.
func (p *Params) CheckEnc(ct *Ciphertext, m, s []int64, w *EncWitness) error {
	N, berr := p.N(), int64(p.lit.BErr)
	if err := checkTernary("s", s, N); err != nil {
		return fmt.Errorf("encryption: %w", err)
	}
	if err := checkBounded("e", w.E, N, berr); err != nil {
		return fmt.Errorf("encryption: %w", err)
	}
	want := p.FromBig(p.ScaleMessage(m))
	want = p.Add(want, p.FromSmall(w.E))
	want = p.Sub(want, p.refMulSmall(ct.C1, s))
	if !p.equal(want, ct.C0) {
		return fmt.Errorf("encryption: c0 != K_enc m + e - c1 s")
	}
	return nil
}

// CheckCase1Eval verifies the relation of the Case 1 pi_eval for the
// ordered ciphertext c, the buyer's key pk and the seller's message m
// (S_bar): c_san = c K_pt m + (b v + e0, a v + e1) + (e_fl X^J, 0), the
// switch witness holds the canonical coefficients of Ext_J(c_san), and
// D = MS_qdel(Ext_J(c_san)) with remainders |r| <= Q/2.
func (p *Params) CheckCase1Eval(c *Ciphertext, pk *PublicKey, m []int64, sw *SanitizeWitness, d *Deliverable, xw *SwitchWitness) error {
	N, berr := p.N(), int64(p.lit.BErr)
	if p.lit.Case != Case1 {
		return fmt.Errorf("pi_eval C1: parameters of case %d", p.lit.Case)
	}
	if err := checkTernary("v", sw.V, N); err != nil {
		return fmt.Errorf("pi_eval C1: %w", err)
	}
	for name, e := range map[string][]int64{"e0": sw.E0, "e1": sw.E1} {
		if err := checkBounded(name, e, N, berr); err != nil {
			return fmt.Errorf("pi_eval C1: %w", err)
		}
	}
	if err := p.checkFlood(sw.EFl); err != nil {
		return fmt.Errorf("pi_eval C1: %w", err)
	}
	pt, err := p.ScalePlain(m)
	if err != nil {
		return err
	}
	c0 := p.Add(p.refMulSmall(c.C0, pt), p.refMulSmall(pk.B, sw.V))
	c0 = p.Add(c0, p.FromSmall(sw.E0))
	p.AddToCoeff(c0, p.lit.J, sw.EFl)
	c1 := p.Add(p.refMulSmall(c.C1, pt), p.refMulSmall(pk.A, sw.V))
	c1 = p.Add(c1, p.FromSmall(sw.E1))
	if p.coeffOf(c0, p.lit.J).Cmp(xw.C0J) != 0 {
		return fmt.Errorf("pi_eval C1: released coefficient of c''_0 differs")
	}
	c1Big := p.ToBig(c1)
	if len(xw.C1) != N || len(d.D1) != N || len(xw.R1) != N {
		return fmt.Errorf("pi_eval C1: deliverable of the wrong size")
	}
	for i := range c1Big {
		if c1Big[i].Cmp(xw.C1[i]) != 0 {
			return fmt.Errorf("pi_eval C1: coefficient %d of c''_1 differs", i)
		}
	}
	if err := p.checkSwitch(xw.C0J, d.D0, xw.R0); err != nil {
		return fmt.Errorf("pi_eval C1: D0: %w", err)
	}
	for i := range xw.C1 {
		if err := p.checkSwitch(xw.C1[i], d.D1[i], xw.R1[i]); err != nil {
			return fmt.Errorf("pi_eval C1: D1[%d]: %w", i, err)
		}
	}
	return nil
}

// checkSwitch verifies Q D~ - q_del c = r with |r| <= Q/2, c in [0, Q),
// D in [0, q_del) and D~ in {D, D + q_del}.
func (p *Params) checkSwitch(c, D, r *big.Int) error {
	if c.Sign() < 0 || c.Cmp(p.q) >= 0 {
		return fmt.Errorf("c = %s not canonical", c)
	}
	if D.Sign() < 0 || D.Cmp(p.lit.QDel) >= 0 {
		return fmt.Errorf("D = %s not in [0, q_del)", D)
	}
	twoR := new(big.Int).Lsh(new(big.Int).Abs(r), 1)
	if twoR.Cmp(p.q) > 0 {
		return fmt.Errorf("remainder %s exceeds Q/2", r)
	}
	lhs := new(big.Int).Mul(p.lit.QDel, c)
	lhs.Add(lhs, r) // = Q D~
	tilde, rem := new(big.Int).QuoRem(lhs, p.q, new(big.Int))
	if rem.Sign() != 0 {
		return fmt.Errorf("q_del c + r is not a multiple of Q")
	}
	if tilde.Cmp(D) != 0 && tilde.Cmp(new(big.Int).Add(D, p.lit.QDel)) != 0 {
		return fmt.Errorf("D~ = %s does not reduce to D = %s", tilde, D)
	}
	return nil
}

// CheckCase2Eval verifies the relation of the Case 2 pi_eval (eq. (3)):
// c2,1 = K_pt m c1,1 + a v + e1' with v ternary and ||e1'||_inf <= B_err.
// The first component c2,0 is not part of the relation.
func (p *Params) CheckCase2Eval(c21, c11 ring.Poly, pk *PublicKey, m []int64, w *ZeroEncWitness) error {
	N := p.N()
	if err := checkTernary("v", w.V, N); err != nil {
		return fmt.Errorf("pi_eval C2: %w", err)
	}
	if err := checkBounded("e1", w.E1, N, int64(p.lit.BErr)); err != nil {
		return fmt.Errorf("pi_eval C2: %w", err)
	}
	pt, err := p.ScalePlain(m)
	if err != nil {
		return err
	}
	want := p.Add(p.refMulSmall(c11, pt), p.refMulSmall(pk.A, w.V))
	want = p.Add(want, p.FromSmall(w.E1))
	if !p.equal(want, c21) {
		return fmt.Errorf("pi_eval C2: c2,1 != w_hat c1,1 + a v + e1'")
	}
	return nil
}

// CheckPDec verifies the relation of pi_dec: p = (c2,1 s)_J + e_fl mod Q
// with s ternary and |e_fl| <= 2^sigma_fl.
func (p *Params) CheckPDec(c21 ring.Poly, s []int64, pd, efl *big.Int) error {
	if err := checkTernary("s", s, p.N()); err != nil {
		return fmt.Errorf("pi_dec: %w", err)
	}
	if err := p.checkFlood(efl); err != nil {
		return fmt.Errorf("pi_dec: %w", err)
	}
	if pd.Sign() < 0 || pd.Cmp(p.q) >= 0 {
		return fmt.Errorf("pi_dec: p not in [0, Q)")
	}
	ref := p.refMulSmall(c21, s)
	want := p.coeffOf(ref, p.lit.J)
	want.Add(want, efl)
	want.Mod(want, p.q)
	if want.Cmp(pd) != 0 {
		return fmt.Errorf("pi_dec: p != (c2,1 s)_J + e_fl")
	}
	return nil
}
