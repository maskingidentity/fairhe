package rlwe

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/big"

	"fairhe/pkg/hashes"

	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// sampler draws secrets, errors and floods from an io.Reader (crypto/rand
// when nil). It is not constant-time; the prototype does not claim
// side-channel resistance.
type sampler struct {
	rng io.Reader
	cdt []uint64 // thresholds of the truncated Gaussian, see newCDT
	b   int
}

func (p *Params) newSampler(rng io.Reader) *sampler {
	if rng == nil {
		rng = rand.Reader
	}
	return &sampler{rng: rng, cdt: newCDT(p.lit.Sigma, p.lit.BErr), b: p.lit.BErr}
}

// newCDT returns the cumulative thresholds of the discrete Gaussian of
// standard deviation sigma restricted to [-b, b]: T_k = floor(2^64 P(X <=
// k - b)) for k = 0 .. 2b-1. A uniform u in [0, 2^64) maps to the smallest k
// with u < T_k, or to b when there is none, so every sample lies in [-b, b]
// exactly; the probabilities are accurate to the float64 precision.
func newCDT(sigma float64, b int) []uint64 {
	w := make([]float64, 2*b+1)
	total := 0.0
	for k := range w {
		x := float64(k - b)
		w[k] = math.Exp(-x * x / (2 * sigma * sigma))
		total += w[k]
	}
	cdt := make([]uint64, 2*b)
	acc := 0.0
	two64 := new(big.Float).SetMantExp(big.NewFloat(1), 64)
	for k := 0; k < 2*b; k++ {
		acc += w[k] / total
		t, _ := new(big.Float).Mul(two64, big.NewFloat(acc)).Uint64()
		cdt[k] = t
	}
	return cdt
}

func (s *sampler) uint64() (uint64, error) {
	var buf [8]byte
	if _, err := io.ReadFull(s.rng, buf[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}

// ternary returns n coefficients uniform on {-1, 0, 1}.
func (s *sampler) ternary(n int) ([]int64, error) {
	out := make([]int64, n)
	buf := make([]byte, 256)
	pos := len(buf)
	for i := 0; i < n; {
		if pos == len(buf) {
			if _, err := io.ReadFull(s.rng, buf); err != nil {
				return nil, err
			}
			pos = 0
		}
		v := buf[pos]
		pos++
		if v >= 255 { // 255 = 3 * 85: reject to stay uniform
			continue
		}
		out[i] = int64(v%3) - 1
		i++
	}
	return out, nil
}

// gaussian returns n coefficients of the truncated discrete Gaussian.
func (s *sampler) gaussian(n int) ([]int64, error) {
	out := make([]int64, n)
	for i := range out {
		u, err := s.uint64()
		if err != nil {
			return nil, err
		}
		k := len(s.cdt)
		for t, th := range s.cdt {
			if u < th {
				k = t
				break
			}
		}
		out[i] = int64(k - s.b)
	}
	return out, nil
}

// flood returns an integer uniform on [-2^sigmaBits, 2^sigmaBits] (the
// 2^(sigmaBits+1)+1 integers of the closed interval), by rejection.
func (s *sampler) flood(sigmaBits int) (*big.Int, error) {
	if sigmaBits < 1 || sigmaBits > 200 {
		return nil, fmt.Errorf("rlwe: flood width %d", sigmaBits)
	}
	nbits := sigmaBits + 2 // draws in [0, 2^(sigmaBits+2)), accepts [0, 2^(sigmaBits+1)]
	nbytes := (nbits + 7) / 8
	top := new(big.Int).Lsh(big.NewInt(1), uint(sigmaBits+1))
	buf := make([]byte, nbytes)
	for {
		if _, err := io.ReadFull(s.rng, buf); err != nil {
			return nil, err
		}
		if extra := nbytes*8 - nbits; extra > 0 {
			buf[0] &= byte(0xff >> extra)
		}
		v := new(big.Int).SetBytes(buf)
		if v.Cmp(top) <= 0 {
			return v.Sub(v, new(big.Int).Rsh(top, 1)), nil
		}
	}
}

// UniformPoly reads a uniform element of R_Q from prng (each RNS limb
// uniform, hence uniform modulo Q by the CRT), as Lattigo's uniform sampler
// does: the bit-exact value depends on the sampler's buffering, so a fresh
// prng must be used per polynomial.
func (p *Params) UniformPoly(prng sampling.PRNG) ring.Poly {
	out := p.ringQ.NewPoly()
	ring.NewUniformSampler(prng, p.ringQ).Read(out)
	return out
}

// CoinPoly returns the public-coin uniform element of seed: H_coin expanded
// by a fresh KeyedPRNG, read in the coefficient domain.
func (p *Params) CoinPoly(seed [32]byte) (ring.Poly, error) {
	prng, err := hashes.CoinPRNG(seed)
	if err != nil {
		return ring.Poly{}, err
	}
	return p.UniformPoly(prng), nil
}

// FreshUniform returns a uniform element of R_Q keyed by 32 bytes of rng
// (crypto/rand when nil): the fresh a' of a Case 1 buyer ciphertext.
func (p *Params) FreshUniform(rng io.Reader) (ring.Poly, error) {
	_, a, err := p.FreshSeededUniform(rng)
	return a, err
}

// FreshSeededUniform draws a 32-byte seed from rng (crypto/rand when nil)
// and returns it with its expansion SeededUniform(seed): a Case 1 buyer
// sends the seed in place of a' (option O5), and the seller expands it.
func (p *Params) FreshSeededUniform(rng io.Reader) ([32]byte, ring.Poly, error) {
	if rng == nil {
		rng = rand.Reader
	}
	var seed [32]byte
	if _, err := io.ReadFull(rng, seed[:]); err != nil {
		return seed, ring.Poly{}, err
	}
	a, err := p.SeededUniform(seed)
	return seed, a, err
}

// SeededUniform expands a 32-byte seed into a uniform element of R_Q with
// Lattigo's keyed PRNG.
func (p *Params) SeededUniform(seed [32]byte) (ring.Poly, error) {
	prng, err := sampling.NewKeyedPRNG(seed[:])
	if err != nil {
		return ring.Poly{}, err
	}
	return p.UniformPoly(prng), nil
}

// SampleFlood exposes the flood distribution of width sigma_fl.
func (p *Params) SampleFlood(rng io.Reader) (*big.Int, error) {
	return p.newSampler(rng).flood(p.lit.SigmaFl)
}

// SampleTernary exposes the ternary distribution.
func (p *Params) SampleTernary(rng io.Reader) ([]int64, error) {
	return p.newSampler(rng).ternary(p.N())
}

// SampleError exposes the truncated Gaussian error distribution.
func (p *Params) SampleError(rng io.Reader) ([]int64, error) {
	return p.newSampler(rng).gaussian(p.N())
}
