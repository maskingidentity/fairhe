package valclass

import (
	"crypto/rand"
	"testing"

	"fairhe/pkg/hashes"
	"fairhe/pkg/valuation"
	"fairhe/pkg/zk/gadgets"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestExpandMatchesValuation(t *testing.T) {
	w := valuation.RandomWeights(3, valuation.WMax)
	if got, want := BFV(valuation.Cols).Expand(w), valuation.ExpandWeights(w); !equal(got, want) {
		t.Fatal("integer expansion differs from package valuation")
	}
	wf := valuation.RandomWeights(4, valuation.WMaxFixedInt)
	if got, want := CKKS(valuation.Cols).Expand(wf), valuation.ExpandWeightsFixed(wf); !equal(got, want) {
		t.Fatal("fixed-point expansion differs from package valuation")
	}
	if BFV(valuation.Cols).M() != valuation.M {
		t.Fatal("class size")
	}
	if BFV(valuation.Cols).WHatNormL1Max().Cmp(valuation.WHatNormL1MaxInt()) != 0 ||
		CKKS(valuation.Cols).WHatNormL1Max().Cmp(valuation.WHatNormL1MaxFixed()) != 0 {
		t.Fatal("w_hat norm bounds differ from package valuation")
	}
}

type weightsCircuit struct {
	W     []frontend.Variable
	Rho   frontend.Variable
	ComF  frontend.Variable `gnark:",public"`
	WHat  []frontend.Variable
	class Class
}

func (c *weightsCircuit) Define(api frontend.API) error {
	wh, err := c.class.Weights(api, gadgets.NewRanger(api), c.W, c.Rho, c.ComF)
	if err != nil {
		return err
	}
	for i := range wh {
		api.AssertIsEqual(wh[i], c.WHat[i])
	}
	return nil
}

func TestWeightsCircuit(t *testing.T) {
	for _, cl := range []Class{BFV(4), CKKS(4)} {
		w := []int64{-cl.WMax, 3, cl.WMax, -7}
		rho := make([]byte, hashes.SaltBytes)
		rand.Read(rho)
		com, err := cl.CommitF(hashes.BN254, w, rho)
		if err != nil {
			t.Fatal(err)
		}
		wh := cl.Expand(w)
		assign := func(w []int64) *weightsCircuit {
			a := &weightsCircuit{W: make([]frontend.Variable, cl.Cols), WHat: make([]frontend.Variable, cl.M()), Rho: rho, ComF: com}
			for j := range w {
				a.W[j] = w[j]
			}
			for i := range wh {
				a.WHat[i] = wh[i]
			}
			return a
		}
		empty := &weightsCircuit{W: make([]frontend.Variable, cl.Cols), WHat: make([]frontend.Variable, cl.M()), class: cl}
		if err := test.IsSolved(empty, assign(w), ecc.BN254.ScalarField()); err != nil {
			t.Fatal(err)
		}
		// A weight above w_max is rejected (also its commitment would differ).
		big := append([]int64(nil), w...)
		big[1] = cl.WMax + 1
		if test.IsSolved(empty, assign(big), ecc.BN254.ScalarField()) == nil {
			t.Fatal("weight above w_max accepted")
		}
	}
}

func equal(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
