package evalc1

import (
	"crypto/rand"
	"math/big"
	"os"
	"testing"

	"fairhe/pkg/adaptor"
	"fairhe/pkg/hashes"
	"fairhe/pkg/rlwe"
	"fairhe/pkg/valuation"
	"fairhe/pkg/zk/sealv8"
	"fairhe/pkg/zk/zkmeasure"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

// TestSealedEvalC1 (option O1): the sealed Case 1 pi_eval accepts the claim
// with D behind h_D, shares h_D with pi_seal over the same packed D and
// salt, and refuses an h_D of another D.
func TestSealedEvalC1(t *testing.T) {
	for _, tc := range []struct {
		lit   rlwe.ParamsLiteral
		xBits int
		xMax  *big.Int
	}{{rlwe.Case1BFV(), 26, nil}, {rlwe.Case1CKKS(), 21, big.NewInt(1 << valuation.FracBits)}} {
		cfg, in, _ := small(t, tc.lit, tc.xBits, tc.xMax)
		etaD := make([]byte, hashes.SaltBytes)
		rand.Read(etaD)
		a, pub, err := AssignSealed(cfg, in, etaD)
		if err != nil {
			t.Fatal(err)
		}
		field := ecc.BLS12_381.ScalarField()
		if err := test.IsSolved(NewSealed(cfg), a, field); err != nil {
			t.Fatalf("%s: sealed claim refused: %v", tc.lit.Name, err)
		}
		k, Y, _ := adaptor.NewWitness()
		_, sp, err := sealv8.Assign(hashes.BLS12381, big.NewInt(42), k, Y.X(), Y.Y(), pub.Elems, etaD)
		if err != nil {
			t.Fatal(err)
		}
		if sp.HD.Cmp(pub.HD) != 0 {
			t.Fatalf("%s: pi_seal and pi_eval disagree on h_D", tc.lit.Name)
		}
		elems := append([]*big.Int(nil), pub.Elems...)
		elems[0] = new(big.Int).Add(elems[0], big.NewInt(1))
		other, _ := sealv8.HD(hashes.BLS12381, elems, etaD)
		bad := *a
		bad.HD = other
		if test.IsSolved(NewSealed(cfg), &bad, field) == nil {
			t.Fatalf("%s: h_D of another D accepted", tc.lit.Name)
		}
	}
}

// TestSealedEvalC1FullScale measures the sealed Case 1 pi_eval of option O1
// at full scale (opt-in), as pi_eval_c1_sealed in results/v8/zk.jsonl.
func TestSealedEvalC1FullScale(t *testing.T) {
	if os.Getenv("FAIRHE_ZK_FULL") == "" || os.Getenv("FAIRHE_ZK_PROVE") == "" {
		t.Skip("set FAIRHE_ZK_FULL=1 FAIRHE_ZK_PROVE=1")
	}
	only := os.Getenv("FAIRHE_ZK_PARAMS")
	for _, lit := range []rlwe.ParamsLiteral{rlwe.Case1BFV(), rlwe.Case1CKKS()} {
		if only != "" && only != lit.Name {
			continue
		}
		p := rlwe.MustParams(lit)
		ds := valuation.Generate(31, valuation.NMax)
		cfg, err := ConfigFor(p, valuation.M, 26, nil, valuation.SNormL1MaxInt())
		wh := valuation.ExpandWeights(valuation.RandomWeights(32, valuation.WMax))
		S := valuation.Stats(ds)
		if lit.Scheme == rlwe.CKKS {
			cfg, err = ConfigFor(p, valuation.M, valuation.FracBits+1, big.NewInt(1<<valuation.FracBits), valuation.SNormL1MaxFixed())
			wh = valuation.ExpandWeightsFixed(valuation.RandomWeights(32, valuation.WMaxFixedInt))
			S = valuation.StatsFixed(ds)
		}
		if err != nil {
			t.Fatal(err)
		}
		in, _ := claim(t, p, valuation.EncodeForward(wh, p.N()), S)
		etaD := make([]byte, hashes.SaltBytes)
		rand.Read(etaD)
		a, _, err := AssignSealed(cfg, in, etaD)
		if err != nil {
			t.Fatal(err)
		}
		res, err := zkmeasure.Measure(ecc.BLS12_381, NewSealed(cfg), a, "pi_eval_c1_sealed", lit.Name)
		if err != nil {
			t.Fatal(err)
		}
		record(t, res)
	}
}
