package rlwe

import (
	"fmt"
	"math"
	"math/big"
)

// ClassBounds are the worst-case bounds of a function class that the
// margins of a parameter set use (not measurements).
type ClassBounds struct {
	// PtNormL1 bounds the l1-norm of the plaintext operand K_pt m at its
	// integer scale: ||S_bar||_1 in Case 1, ||w_hat||_1 in Case 2.
	PtNormL1 *big.Int
	// FMax bounds |f|: an integer for BFV, a real value for CKKS.
	FMax *big.Rat
}

// MarginReport lists the margins of a parameter set against a class.
type MarginReport struct {
	Name          string
	LogQ          float64
	LogQDel       float64 // Case 1
	LogB          float64 // worst-case noise at the released coefficient
	SigmaRequired int
	SigmaFl       int
	// DecodeTerm is the left side of the BFV decoding condition (< 1/2).
	DecodeTerm float64
	// LogTau is log2 of the CKKS tolerance.
	LogTau float64
	// LogWrapHeadroom is log2((Q/2) / lhs) of the CKKS no-wrap condition (> 0).
	LogWrapHeadroom float64
	Failures        []string
}

// OK reports whether every margin holds.
func (r MarginReport) OK() bool { return len(r.Failures) == 0 }

// WorstCaseNoise returns the bound B that the flood must cover at the
// released coefficient: B_tot = ||pt||_1 B_c + (2N+1) B_err in Case 1
// (eq. (1)) and B_e = ||pt||_1 B_c1 + 2N B_err in Case 2 (eq. (4)), with
// B_c = B_c1 = B_err since the encrypting party uses its secret key.
func (p *Params) WorstCaseNoise(cb ClassBounds) *big.Int {
	B := new(big.Int).Mul(cb.PtNormL1, big.NewInt(int64(p.lit.BErr)))
	rer := int64(2 * p.N())
	if p.lit.Case == Case1 {
		rer++
	}
	return B.Add(B, big.NewInt(rer*int64(p.lit.BErr)))
}

// RequiredSigma returns the smallest sigma with
// sigma >= lambda_s + log2|J| + log2 B - 1 (Lemma 1, |J| = 1), i.e. the
// smallest sigma with B 2^lambda_s <= 2^(sigma+1).
func (p *Params) RequiredSigma(B *big.Int) int {
	t := new(big.Int).Lsh(B, uint(p.lit.LambdaS))
	L := t.BitLen()
	pow2 := new(big.Int).Lsh(big.NewInt(1), uint(L-1))
	if t.Cmp(pow2) == 0 {
		return L - 2
	}
	return L - 1
}

// CheckMargins evaluates the flood width, the decoding condition or the
// CKKS tolerance and no-wrap condition of the set's case, and the margins of
// Appendix C.4, all in exact rational arithmetic.
func (p *Params) CheckMargins(cb ClassBounds) MarginReport {
	rep := MarginReport{Name: p.lit.Name, LogQ: log2Big(p.q), SigmaFl: p.lit.SigmaFl}
	fail := func(format string, args ...any) {
		rep.Failures = append(rep.Failures, fmt.Sprintf(format, args...))
	}
	B := p.WorstCaseNoise(cb)
	rep.LogB = log2Big(B)
	rep.SigmaRequired = p.RequiredSigma(B)
	if p.lit.SigmaFl < rep.SigmaRequired {
		fail("sigma_fl = %d below the required %d", p.lit.SigmaFl, rep.SigmaRequired)
	}

	N := int64(p.N())
	Q := new(big.Rat).SetInt(p.q)
	flood := new(big.Rat).SetInt(new(big.Int).Lsh(big.NewInt(1), uint(p.lit.SigmaFl)))
	Br := new(big.Rat).SetInt(B)
	berr := big.NewRat(int64(p.lit.BErr), 1)
	half := big.NewRat(1, 2)
	var qdel *big.Rat
	if p.lit.Case == Case1 {
		qdel = new(big.Rat).SetInt(p.lit.QDel)
		rep.LogQDel = log2Big(p.lit.QDel)
	}

	switch p.lit.Scheme {
	case BFV:
		// t (B [+ B_err] + 2^sigma) / Q  [+ t (N+1) / (2 q_del)]  + f_max (Q mod t) / Q < 1/2
		tR := new(big.Rat).SetInt(p.t)
		noise := new(big.Rat).Add(Br, flood)
		if p.lit.Case == Case2 {
			noise.Add(noise, berr) // the buyer's own e0'
		}
		term := new(big.Rat).Mul(tR, noise)
		term.Quo(term, Q)
		if p.lit.Case == Case1 {
			sw := new(big.Rat).Mul(tR, big.NewRat(N+1, 2))
			term.Add(term, sw.Quo(sw, qdel))
		}
		qModT := new(big.Rat).SetInt(new(big.Int).Mod(p.q, p.t))
		ovf := new(big.Rat).Mul(cb.FMax, qModT)
		term.Add(term, ovf.Quo(ovf, Q))
		rep.DecodeTerm, _ = term.Float64()
		if term.Cmp(half) >= 0 {
			fail("BFV decoding term %.6f >= 1/2", rep.DecodeTerm)
		}
		if new(big.Rat).SetInt(p.t).Cmp(new(big.Rat).Mul(cb.FMax, big.NewRat(2, 1))) <= 0 {
			fail("t = 2^%d does not exceed twice the largest output", p.lit.LogT)
		}
	case CKKS:
		delta := new(big.Rat).SetInt(p.ResultScale())
		lhs := new(big.Rat).Mul(delta, cb.FMax)
		lhs.Add(lhs, flood)
		lhs.Add(lhs, Br)
		tau := new(big.Rat).Add(flood, Br)
		if p.lit.Case == Case1 {
			sw := new(big.Rat).Mul(big.NewRat(N+1, 2), Q)
			sw.Quo(sw, qdel)
			lhs.Add(lhs, sw)
			tau.Quo(tau, delta)
			tau.Add(tau, new(big.Rat).Quo(sw, delta))
		} else {
			lhs.Add(lhs, berr)
			tau.Add(tau, berr)
			tau.Quo(tau, delta)
		}
		halfQ := new(big.Rat).Mul(Q, half)
		rep.LogWrapHeadroom = log2Rat(new(big.Rat).Quo(halfQ, lhs))
		if lhs.Cmp(halfQ) >= 0 {
			fail("CKKS result wraps around: headroom 2^%.4f", rep.LogWrapHeadroom)
		}
		rep.LogTau = log2Rat(tau)
		if rep.LogTau > p.lit.LogTauMax {
			fail("CKKS tolerance 2^%.4f above 2^%.3f", rep.LogTau, p.lit.LogTauMax)
		}
	}

	// Margins of Appendix C.4 and the HE standard's 218-bit ceiling for
	// 128-bit security at N = 2^13.
	if m := p.lit.PaperLogQMin; m > 0 {
		if p.lit.PaperLogQStrict && !(rep.LogQ > m) || !p.lit.PaperLogQStrict && rep.LogQ < m {
			fail("log2 Q = %.6f misses the margin %.2f", rep.LogQ, m)
		}
	}
	if m := p.lit.PaperLogQDelMin; m > 0 && rep.LogQDel < m {
		fail("log2 q_del = %.6f below %.2f", rep.LogQDel, m)
	}
	if m := p.lit.PaperLogQOverQDelMax; m > 0 && !(rep.LogQ-rep.LogQDel < m) {
		fail("log2(Q/q_del) = %.6f not below %.2f", rep.LogQ-rep.LogQDel, m)
	}
	if rep.LogQ > 218 {
		fail("log2 Q = %.2f above the 218 bits of the HE standard", rep.LogQ)
	}
	return rep
}

func log2Rat(r *big.Rat) float64 {
	if r.Sign() <= 0 {
		return math.Inf(-1)
	}
	return log2Big(r.Num()) - log2Big(r.Denom())
}
