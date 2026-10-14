package decproof

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
	"fairhe/pkg/zk/valclass"
	"fairhe/pkg/zk/zkmeasure"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

// TestSealedDecProof (option O1): the sealed pi_dec accepts the claim with p
// behind h_D, shares h_D with pi_seal over the same p and salt, and refuses
// an h_D of another p.
func TestSealedDecProof(t *testing.T) {
	for _, tc := range []struct {
		lit rlwe.ParamsLiteral
		cl  valclass.Class
	}{{rlwe.Case2BFV(), valclass.BFV(2)}, {rlwe.Case2CKKS(), valclass.CKKS(2)}} {
		in := smallInstance(t, tc.lit, tc.cl)
		etaD := make([]byte, hashes.SaltBytes)
		rand.Read(etaD)
		a, pub, err := AssignSealed(in.cfg, big.NewInt(42), in.c21, in.slot.KeyWitness.S, in.slot.Eta, in.pd, in.efl, etaD)
		if err != nil {
			t.Fatal(err)
		}
		field := ecc.BN254.ScalarField()
		if err := test.IsSolved(NewSealed(in.cfg), a, field); err != nil {
			t.Fatalf("%s: sealed claim refused: %v", tc.lit.Name, err)
		}
		k, Y, _ := adaptor.NewWitness()
		_, sp, err := sealv8.Assign(hashes.BN254, big.NewInt(42), k, Y.X(), Y.Y(), []*big.Int{in.pd}, etaD)
		if err != nil {
			t.Fatal(err)
		}
		if sp.HD.Cmp(pub.HD) != 0 {
			t.Fatalf("%s: pi_seal and pi_dec disagree on h_D", tc.lit.Name)
		}
		other, _ := sealv8.HD(hashes.BN254, []*big.Int{new(big.Int).Add(in.pd, big.NewInt(1))}, etaD)
		bad := *a
		bad.HD = other
		if test.IsSolved(NewSealed(in.cfg), &bad, field) == nil {
			t.Fatalf("%s: h_D of another p accepted", tc.lit.Name)
		}
	}
}

// TestSealedDecProofFullScale measures the sealed pi_dec of option O1 at
// full scale (opt-in), as pi_dec_sealed in results/v8/zk.jsonl.
func TestSealedDecProofFullScale(t *testing.T) {
	if os.Getenv("FAIRHE_ZK_FULL") == "" || os.Getenv("FAIRHE_ZK_PROVE") == "" {
		t.Skip("set FAIRHE_ZK_FULL=1 FAIRHE_ZK_PROVE=1")
	}
	only := os.Getenv("FAIRHE_ZK_PARAMS")
	ds := valuation.Generate(71, valuation.NMax)
	for _, tc := range []struct {
		lit rlwe.ParamsLiteral
		cl  valclass.Class
		S   []int64
		w   []int64
	}{
		{rlwe.Case2BFV(), valclass.BFV(valuation.Cols), valuation.Stats(ds), valuation.RandomWeights(72, valuation.WMax)},
		{rlwe.Case2CKKS(), valclass.CKKS(valuation.Cols), valuation.StatsFixed(ds), valuation.RandomWeights(73, valuation.WMaxFixedInt)},
	} {
		if only != "" && only != tc.lit.Name {
			continue
		}
		in := newInstance(t, tc.lit, tc.cl, tc.S, tc.w)
		etaD := make([]byte, hashes.SaltBytes)
		rand.Read(etaD)
		a, _, err := AssignSealed(in.cfg, big.NewInt(42), in.c21, in.slot.KeyWitness.S, in.slot.Eta, in.pd, in.efl, etaD)
		if err != nil {
			t.Fatal(err)
		}
		res, err := zkmeasure.Measure(ecc.BN254, NewSealed(in.cfg), a, "pi_dec_sealed", tc.lit.Name)
		if err != nil {
			t.Fatal(err)
		}
		res.FillMemory()
		if err := zkmeasure.Append("zk.jsonl", res); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s/%s: %d constraints, setup %.1fs, prove %.2fs, verify %.3fs, peak commit %.2f GiB",
			res.Circuit, res.Params, res.Constraints, res.SetupS, res.ProveS, res.VerifyS, res.PeakCommitGiB)
	}
}
