// Package valclass expresses the class of the running example in circuits:
// weights w with ||w||_inf <= w_max that open Com(f), their expansion
// w_hat = ((w_j^2), (2 w_j w_k)_{j<k}, (-2^(beta+1) u w_j), 2^(2 beta) u^2)
// in the order of package valuation, and the data commitment Com(x). The
// number of columns is a parameter so that reduced instances can be tested;
// Cols = 31 is the class of the paper (m = 528).
package valclass

import (
	"fmt"
	"math/big"

	"fairhe/pkg/hashes"
	"fairhe/pkg/valuation"
	"fairhe/pkg/zk/gadgets"

	"github.com/consensys/gnark/frontend"
)

// Labels of the commitments.
const (
	LabelF = "f"
	LabelX = "x"
)

// Class fixes the constants of the class for one scheme.
type Class struct {
	Cols  int
	WMax  int64 // |w_j| <= WMax
	Beta  int
	Unit  int64 // 1 for BFV, 2^10 for the fixed-point (CKKS) version
	FBits int   // bits of the offset weights w_j + WMax in Com(f)
	XBits int   // bits of an entry of S in Com(x)
}

// M returns the number of entries of S and w_hat.
func (c Class) M() int { return c.Cols*(c.Cols+1)/2 + c.Cols + 1 }

// BFV returns the integer class of the paper (or a reduced one with cols).
func BFV(cols int) Class {
	return Class{Cols: cols, WMax: valuation.WMax, Beta: valuation.Beta, Unit: 1, FBits: 9, XBits: 26}
}

// CKKS returns the fixed-point class of the paper (or a reduced one).
func CKKS(cols int) Class {
	return Class{Cols: cols, WMax: valuation.WMaxFixedInt, Beta: 0, Unit: 1 << valuation.WFracBits, FBits: 16, XBits: valuation.FracBits + 1}
}

// Pairs returns the (j, k) pairs of the quadratic block: the diagonal, then
// j < k in lexicographic order.
func (c Class) Pairs() [][2]int {
	ps := make([][2]int, 0, c.Cols*(c.Cols+1)/2)
	for j := 0; j < c.Cols; j++ {
		ps = append(ps, [2]int{j, j})
	}
	for j := 0; j < c.Cols; j++ {
		for k := j + 1; k < c.Cols; k++ {
			ps = append(ps, [2]int{j, k})
		}
	}
	return ps
}

// Expand returns w_hat natively.
func (c Class) Expand(w []int64) []int64 {
	out := make([]int64, 0, c.M())
	for _, p := range c.Pairs() {
		if p[0] == p[1] {
			out = append(out, w[p[0]]*w[p[0]])
		} else {
			out = append(out, 2*w[p[0]]*w[p[1]])
		}
	}
	for j := 0; j < c.Cols; j++ {
		out = append(out, -(int64(1)<<(c.Beta+1))*c.Unit*w[j])
	}
	return append(out, (int64(1)<<(2*c.Beta))*c.Unit*c.Unit)
}

// Offsets returns w_j + WMax, the unsigned values committed in Com(f).
func (c Class) Offsets(w []int64) []*big.Int {
	out := make([]*big.Int, len(w))
	for j, x := range w {
		out[j] = big.NewInt(x + c.WMax)
	}
	return out
}

// CommitF returns Com(f) natively over the field of the case.
func (c Class) CommitF(f hashes.Field, w []int64, rho []byte) (*big.Int, error) {
	if len(w) != c.Cols {
		return nil, fmt.Errorf("valclass: %d weights, want %d", len(w), c.Cols)
	}
	return hashes.Commit(f, LabelF, c.Offsets(w), c.FBits, rho)
}

// CommitX returns Com(x) natively over the field of the case.
func (c Class) CommitX(f hashes.Field, S []int64, rho []byte) (*big.Int, error) {
	return hashes.Commit(f, LabelX, gadgets.Ints(S), c.XBits, rho)
}

// Weights constrains ||w||_inf <= WMax, opens Com(f) with the salt rho and
// returns w_hat as circuit variables (M entries, in the order of Expand).
func (c Class) Weights(api frontend.API, rg *gadgets.Ranger, w []frontend.Variable, rho, comF frontend.Variable) ([]frontend.Variable, error) {
	if len(w) != c.Cols {
		return nil, fmt.Errorf("valclass: %d weight variables, want %d", len(w), c.Cols)
	}
	off := make([]frontend.Variable, c.Cols)
	wmax := big.NewInt(c.WMax)
	for j, x := range w {
		rg.InSym(x, wmax)
		off[j] = api.Add(x, c.WMax)
	}
	rg.Bits(rho, 8*hashes.SaltBytes)
	com, err := gadgets.Commitment(api, LabelF, off, c.FBits, rho)
	if err != nil {
		return nil, err
	}
	api.AssertIsEqual(com, comF)
	wh := make([]frontend.Variable, 0, c.M())
	for _, p := range c.Pairs() {
		if p[0] == p[1] {
			wh = append(wh, api.Mul(w[p[0]], w[p[0]]))
		} else {
			wh = append(wh, api.Mul(2, w[p[0]], w[p[1]]))
		}
	}
	lin := new(big.Int).Lsh(big.NewInt(c.Unit), uint(c.Beta+1))
	lin.Neg(lin)
	for j := 0; j < c.Cols; j++ {
		wh = append(wh, api.Mul(w[j], lin))
	}
	cst := new(big.Int).Lsh(big.NewInt(c.Unit*c.Unit), uint(2*c.Beta))
	return append(wh, frontend.Variable(cst)), nil
}

// Data constrains the entries of S to XBits bits and opens Com(x).
func (c Class) Data(api frontend.API, rg *gadgets.Ranger, x []frontend.Variable, rho, comX frontend.Variable) error {
	for _, v := range x {
		rg.Bits(v, c.XBits)
	}
	rg.Bits(rho, 8*hashes.SaltBytes)
	com, err := gadgets.Commitment(api, LabelX, x, c.XBits, rho)
	if err != nil {
		return err
	}
	api.AssertIsEqual(com, comX)
	return nil
}

// WHatNormL1Max bounds ||w_hat||_1 = (||w||_1 + 2^beta u)... in the units of
// the class: (Cols WMax + 2^beta u)^2 for both versions.
func (c Class) WHatNormL1Max() *big.Int {
	v := big.NewInt(int64(c.Cols)*c.WMax + (int64(1)<<c.Beta)*c.Unit)
	return v.Mul(v, v)
}
