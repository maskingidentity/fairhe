package gadgets

import (
	"fmt"
	"math/big"
	"math/bits"
	"sync"

	"fairhe/pkg/hashes"

	"github.com/consensys/gnark/frontend"
)

// The blob link of the Case 1 claim: an EIP-4844 blob holds 4096 elements of
// the BLS12-381 scalar field as the evaluations of a polynomial P of degree
// below 4096 on the roots of unity in bit-reversed order, and the point
// evaluation precompile checks a KZG opening P(z) = y. The circuit computes
// the same y from the deliverable's packed elements by the barycentric
// formula of the EIP-4844 specification,
//
//	P(z) = (z^n - 1) / n * sum_i y_i w_i / (z - w_i),
//
// natively over BLS12-381, at about one constraint per
// nonzero element.

// BlobWidth is the number of field elements of a blob.
const BlobWidth = 4096

var (
	blobRootsOnce sync.Once
	blobRoots     []*big.Int // roots of unity of order 4096 in bit-reversed order
)

// BlobRoots returns the evaluation domain of a blob: w_i = omega^bitrev(i)
// with omega = 7^((r - 1) / 4096) mod r_bls, as in EIP-4844.
func BlobRoots() []*big.Int {
	blobRootsOnce.Do(func() {
		r := hashes.BLSModulus()
		e := new(big.Int).Sub(r, big.NewInt(1))
		e.Div(e, big.NewInt(BlobWidth))
		omega := new(big.Int).Exp(big.NewInt(7), e, r)
		natural := make([]*big.Int, BlobWidth)
		natural[0] = big.NewInt(1)
		for i := 1; i < BlobWidth; i++ {
			natural[i] = new(big.Int).Mul(natural[i-1], omega)
			natural[i].Mod(natural[i], r)
		}
		blobRoots = make([]*big.Int, BlobWidth)
		for i := range blobRoots {
			blobRoots[i] = natural[bits.Reverse16(uint16(i))>>4]
		}
	})
	return blobRoots
}

// BlobEvalNative returns P(z) for the blob whose first elements are elems
// (the rest zero), by the barycentric formula; z must not be a root of unity.
func BlobEvalNative(elems []*big.Int, z *big.Int) (*big.Int, error) {
	if len(elems) > BlobWidth {
		return nil, fmt.Errorf("gadgets: %d elements exceed a blob", len(elems))
	}
	r := hashes.BLSModulus()
	roots := BlobRoots()
	acc := new(big.Int)
	t := new(big.Int)
	for i, y := range elems {
		d := new(big.Int).Sub(z, roots[i])
		d.Mod(d, r)
		if d.Sign() == 0 {
			return nil, fmt.Errorf("gadgets: z is a root of unity")
		}
		d.ModInverse(d, r)
		t.Mul(y, roots[i])
		t.Mul(t, d)
		acc.Add(acc, t).Mod(acc, r)
	}
	zn := new(big.Int).Exp(z, big.NewInt(BlobWidth), r)
	zn.Sub(zn, big.NewInt(1))
	invN := new(big.Int).ModInverse(big.NewInt(BlobWidth), r)
	acc.Mul(acc, zn).Mul(acc, invN)
	return acc.Mod(acc, r), nil
}

// BlobEval returns P(z) in a BLS12-381 circuit for the blob whose first
// elements are elems (the rest zero). Each element costs one constraint
// q_i (z - w_i) = y_i w_i; a z on the domain makes the circuit
// unsatisfiable, which a random z avoids except with probability 2^-242.
func BlobEval(api frontend.API, elems []frontend.Variable, z frontend.Variable) (frontend.Variable, error) {
	f, err := FieldOf(api)
	if err != nil {
		return nil, err
	}
	if f != hashes.BLS12381 {
		return nil, fmt.Errorf("gadgets: blob evaluation is native to BLS12-381 only")
	}
	if len(elems) > BlobWidth {
		return nil, fmt.Errorf("gadgets: %d elements exceed a blob", len(elems))
	}
	roots := BlobRoots()
	terms := make([]frontend.Variable, len(elems))
	for i, y := range elems {
		terms[i] = api.Div(api.Mul(y, roots[i]), api.Sub(z, roots[i]))
	}
	acc := sum(api, terms)
	zn := z
	for k := 0; k < 12; k++ { // z^4096
		zn = api.Mul(zn, zn)
	}
	invN := new(big.Int).ModInverse(big.NewInt(BlobWidth), hashes.BLSModulus())
	return api.Mul(acc, api.Sub(zn, 1), invN), nil
}
