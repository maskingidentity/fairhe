// Package rlwe implements the homomorphic-encryption layer of the paper
// (Definition 1 and the coefficient-level operations of Section 2) as
// textbook BFV and coefficient-encoded CKKS on Lattigo's ring package:
// secret-key encryption with public-coin or fresh uniform
// components, plaintext-ciphertext products with centred integer operands,
// sanitisation, extraction of the released coefficient, modulus switching to
// a delivery modulus, and flooded partial decryption.
//
// Everything lives in the coefficient domain; Lattigo's NTT is used only to
// multiply. Lattigo's own BGV/BFV encoder is not used: it lifts a message to
// m t^-1 mod Q rather than Delta m and requires a prime t below the first
// modulus, which excludes the t = 2^53 of the running example, and its
// encryptor does not return the error that the proofs take as a witness.
package rlwe

import (
	"fmt"
	"math"
	"math/big"

	"github.com/tuneinsight/lattigo/v6/ring"
)

// Scheme is the encoding of the scale.
type Scheme int

const (
	// BFV is exact: Delta = floor(Q/t), decoding round(t x / modulus) mod t.
	BFV Scheme = iota
	// CKKS is approximate with coefficient encoding: the scale is a power of
	// two and decoding divides by it.
	CKKS
)

func (s Scheme) String() string {
	if s == BFV {
		return "BFV"
	}
	return "CKKS"
}

// Case is the protocol that a parameter set serves.
type Case int

const (
	// Case1: the buyer encrypts the function, the seller evaluates on its
	// plaintext data, sanitises, extracts and switches to q_del.
	Case1 Case = 1
	// Case2: the seller encrypts the data, the buyer evaluates and
	// re-randomises, the seller partially decrypts the released coefficient.
	Case2 Case = 2
)

// ParamsLiteral fixes one parameter set.
type ParamsLiteral struct {
	Name   string
	Scheme Scheme
	Case   Case
	LogN   int

	// Q are the NTT-friendly primes (q_i = 1 mod 2N) of the modulus at which
	// the product is computed and the flood is added, given explicitly rather
	// than as bit sizes so that the modulus is reproducible.
	Q []uint64

	// LogT: BFV plaintext modulus t = 2^LogT.
	LogT int

	// LogScaleEnc, LogScalePt: CKKS scales of the encrypted and of the
	// plaintext operand; the result has scale 2^(LogScaleEnc + LogScalePt).
	LogScaleEnc, LogScalePt int
	// FracBits: both CKKS operands are integers in units of 2^-FracBits.
	FracBits int

	// QDel is the Case 1 delivery modulus (nil in Case 2).
	QDel *big.Int

	// SigmaFl: the flood is uniform on [-2^SigmaFl, 2^SigmaFl].
	SigmaFl int
	// BErr bounds every fresh error; Sigma is the standard deviation of the
	// discrete Gaussian that is truncated at BErr.
	BErr  int
	Sigma float64
	// LambdaS is the statistical security parameter of the flood.
	LambdaS int
	// J is the released coefficient (|J| = 1).
	J int

	// Margins of Appendix C.4 that the chain must keep (log2; 0 = none).
	PaperLogQMin         float64 // Q >= 2^PaperLogQMin (strict when PaperLogQStrict)
	PaperLogQStrict      bool
	PaperLogQDelMin      float64 // q_del >= 2^PaperLogQDelMin
	PaperLogQOverQDelMax float64 // Q / q_del < 2^PaperLogQOverQDelMax
	// LogTauMax is the CKKS tolerance of the terms: tau <= 2^LogTauMax.
	LogTauMax float64
}

// Params is a validated parameter set with its ring and derived constants.
type Params struct {
	lit   ParamsLiteral
	ringQ *ring.Ring
	q     *big.Int
	t     *big.Int // BFV
	delta *big.Int // BFV: floor(Q/t)
	crt   []*big.Int
}

// NewParams validates a literal and builds its ring.
func NewParams(lit ParamsLiteral) (*Params, error) {
	N := 1 << lit.LogN
	if lit.LogN < 1 || lit.LogN > 17 {
		return nil, fmt.Errorf("rlwe: LogN = %d", lit.LogN)
	}
	if len(lit.Q) == 0 {
		return nil, fmt.Errorf("rlwe: empty modulus chain")
	}
	for _, qi := range lit.Q {
		if qi%uint64(2*N) != 1 {
			return nil, fmt.Errorf("rlwe: prime %d is not 1 mod 2N", qi)
		}
		if qi >= 1<<61 {
			return nil, fmt.Errorf("rlwe: prime %d exceeds 61 bits", qi)
		}
		if !new(big.Int).SetUint64(qi).ProbablyPrime(40) {
			return nil, fmt.Errorf("rlwe: %d is not prime", qi)
		}
	}
	ringQ, err := ring.NewRing(N, lit.Q)
	if err != nil {
		return nil, fmt.Errorf("rlwe: %w", err)
	}
	p := &Params{lit: lit, ringQ: ringQ, q: ringQ.Modulus()}
	if lit.J < 0 || lit.J >= N {
		return nil, fmt.Errorf("rlwe: released coefficient %d outside [0, N)", lit.J)
	}
	switch lit.Scheme {
	case BFV:
		if lit.LogT < 2 {
			return nil, fmt.Errorf("rlwe: BFV needs LogT >= 2")
		}
		p.t = new(big.Int).Lsh(big.NewInt(1), uint(lit.LogT))
		p.delta = new(big.Int).Quo(p.q, p.t)
	case CKKS:
		if lit.LogScaleEnc < lit.FracBits || lit.LogScalePt < lit.FracBits {
			return nil, fmt.Errorf("rlwe: CKKS scales must be at least 2^FracBits")
		}
	default:
		return nil, fmt.Errorf("rlwe: unknown scheme")
	}
	switch lit.Case {
	case Case1:
		if lit.QDel == nil || lit.QDel.Sign() <= 0 || lit.QDel.Cmp(p.q) >= 0 {
			return nil, fmt.Errorf("rlwe: Case 1 needs a delivery modulus 0 < q_del < Q")
		}
	case Case2:
		if lit.QDel != nil {
			return nil, fmt.Errorf("rlwe: Case 2 has no delivery modulus")
		}
	default:
		return nil, fmt.Errorf("rlwe: unknown case")
	}
	if lit.BErr < 1 || lit.SigmaFl < 1 {
		return nil, fmt.Errorf("rlwe: BErr and SigmaFl must be positive")
	}
	// CRT basis: crt_i = (Q/q_i) * ((Q/q_i)^-1 mod q_i).
	for _, qi := range lit.Q {
		qb := new(big.Int).SetUint64(qi)
		qhat := new(big.Int).Quo(p.q, qb)
		inv := new(big.Int).ModInverse(new(big.Int).Mod(qhat, qb), qb)
		p.crt = append(p.crt, qhat.Mul(qhat, inv))
	}
	return p, nil
}

// MustParams is NewParams for the fixed literals of this package.
func MustParams(lit ParamsLiteral) *Params {
	p, err := NewParams(lit)
	if err != nil {
		panic(err)
	}
	return p
}

// Literal returns the literal the parameters were built from.
func (p *Params) Literal() ParamsLiteral { return p.lit }

// Name returns the name of the parameter set.
func (p *Params) Name() string { return p.lit.Name }

// Scheme returns the encoding of the scale.
func (p *Params) Scheme() Scheme { return p.lit.Scheme }

// Case returns the protocol the set serves.
func (p *Params) Case() Case { return p.lit.Case }

// N returns the ring degree.
func (p *Params) N() int { return 1 << p.lit.LogN }

// RingQ returns the ring R_Q.
func (p *Params) RingQ() *ring.Ring { return p.ringQ }

// Q returns the modulus Q (a copy).
func (p *Params) Q() *big.Int { return new(big.Int).Set(p.q) }

// LogQ returns log2 Q.
func (p *Params) LogQ() float64 { return log2Big(p.q) }

// QDel returns the Case 1 delivery modulus (a copy; nil in Case 2).
func (p *Params) QDel() *big.Int {
	if p.lit.QDel == nil {
		return nil
	}
	return new(big.Int).Set(p.lit.QDel)
}

// T returns the BFV plaintext modulus (nil for CKKS).
func (p *Params) T() *big.Int {
	if p.t == nil {
		return nil
	}
	return new(big.Int).Set(p.t)
}

// J returns the released coefficient.
func (p *Params) J() int { return p.lit.J }

// SigmaFl returns the flood width.
func (p *Params) SigmaFl() int { return p.lit.SigmaFl }

// BErr returns the error bound.
func (p *Params) BErr() int { return p.lit.BErr }

// EncScale returns K_enc, the factor by which the encrypted operand's integer
// message is scaled into the plaintext polynomial: Delta = floor(Q/t) for
// BFV, 2^(LogScaleEnc - FracBits) for CKKS.
func (p *Params) EncScale() *big.Int {
	if p.lit.Scheme == BFV {
		return new(big.Int).Set(p.delta)
	}
	return new(big.Int).Lsh(big.NewInt(1), uint(p.lit.LogScaleEnc-p.lit.FracBits))
}

// PtScale returns K_pt, the factor applied to the plaintext operand's
// integer message: 1 for BFV, 2^(LogScalePt - FracBits) for CKKS.
func (p *Params) PtScale() int64 {
	if p.lit.Scheme == BFV {
		return 1
	}
	return int64(1) << (p.lit.LogScalePt - p.lit.FracBits)
}

// ResultScale returns the CKKS scale of the result, 2^(LogScaleEnc +
// LogScalePt), relative to the real output (nil for BFV).
func (p *Params) ResultScale() *big.Int {
	if p.lit.Scheme == BFV {
		return nil
	}
	return new(big.Int).Lsh(big.NewInt(1), uint(p.lit.LogScaleEnc+p.lit.LogScalePt))
}

// DecodeBFV returns round(t x / modulus) mod t for x in [0, modulus), the
// BFV decoding of a raw decryption modulo Q (Case 2) or q_del (Case 1).
func (p *Params) DecodeBFV(x, modulus *big.Int) *big.Int {
	if p.t == nil {
		panic("rlwe: DecodeBFV on CKKS parameters")
	}
	num := new(big.Int).Mul(p.t, x)
	r := roundDiv(num, modulus)
	return r.Mod(r, p.t)
}

// DecodeCKKS returns x / Delta' for the centred representative of x modulo
// modulus, where Delta' = ResultScale * modulus / Q is the scale after a
// switch from Q to modulus (Delta' = ResultScale when modulus = Q).
func (p *Params) DecodeCKKS(x, modulus *big.Int) *big.Rat {
	if p.t != nil {
		panic("rlwe: DecodeCKKS on BFV parameters")
	}
	c := centred(x, modulus)
	den := new(big.Int).Mul(p.ResultScale(), modulus)
	num := new(big.Int).Mul(c, p.q)
	return new(big.Rat).SetFrac(num, den)
}

// coeffOf returns coefficient j of a ring element by CRT, in [0, Q).
func (p *Params) coeffOf(a ring.Poly, j int) *big.Int {
	acc := new(big.Int)
	t := new(big.Int)
	for i := range p.lit.Q {
		acc.Add(acc, t.Mul(t.SetUint64(a.Coeffs[i][j]), p.crt[i]))
	}
	return acc.Mod(acc, p.q)
}

// roundDiv returns round(a / b) for b > 0 (halves away from zero).
func roundDiv(a, b *big.Int) *big.Int {
	twice := new(big.Int).Lsh(a, 1)
	if a.Sign() >= 0 {
		twice.Add(twice, b)
	} else {
		twice.Sub(twice, b)
	}
	den := new(big.Int).Lsh(b, 1)
	return twice.Quo(twice, den) // Quo truncates toward zero
}

// centred returns the representative of x mod m in (-m/2, m/2].
func centred(x, m *big.Int) *big.Int {
	c := new(big.Int).Mod(x, m)
	half := new(big.Int).Rsh(m, 1)
	if c.Cmp(half) > 0 {
		c.Sub(c, m)
	}
	return c
}

// log2Big returns log2 of a positive integer with float64 precision on the
// mantissa (exact enough for margins far from integer boundaries).
func log2Big(x *big.Int) float64 {
	if x.Sign() <= 0 {
		return math.Inf(-1)
	}
	shift := x.BitLen() - 64
	if shift < 0 {
		shift = 0
	}
	top := new(big.Int).Rsh(x, uint(shift))
	f, _ := new(big.Float).SetInt(top).Float64()
	return math.Log2(f) + float64(shift)
}
