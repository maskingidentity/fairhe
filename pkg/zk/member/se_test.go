package member

// Option O2: pi_member with straight-line
// extraction of w, its extractor, and its full-scale cost (opt-in):
//
//	FAIRHE_ZK_FULL=1 FAIRHE_ZK_PROVE=1 FAIRHE_ZK_REPS=5 go test ./pkg/zk/member -run TestO2SEFullScale -v

import (
	"crypto/rand"
	"math/big"
	"os"
	"strconv"
	"testing"

	"fairhe/pkg/hashes"
	"fairhe/pkg/rlwe"
	"fairhe/pkg/valuation"
	"fairhe/pkg/zk/se"
	"fairhe/pkg/zk/valclass"
	"fairhe/pkg/zk/zkmeasure"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// TestO2SE: the SE circuit accepts an honest order, the extractor reads w
// from the public (R, CT) with the setup's secret, and an encryption of
// other weights than the witness is refused.
func TestO2SE(t *testing.T) {
	for _, tc := range []struct {
		lit rlwe.ParamsLiteral
		cl  valclass.Class
	}{{rlwe.Case1BFV(), valclass.BFV(2)}, {rlwe.Case1CKKS(), valclass.CKKS(2)}} {
		lit := tc.lit
		lit.LogN, lit.J = 6, tc.cl.M()-1
		w := []int64{-tc.cl.WMax, tc.cl.WMax / 3}
		in := newInstance(t, lit, tc.cl, w)
		sk, pk, err := se.KeyGen(hashes.BLS12381, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		c, err := AssignSE(in.cfg, pk, in.p, in.ct, in.w, in.rhoF, in.sk.S, in.eta, in.ew, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		field := ecc.BLS12_381.ScalarField()
		if err := test.IsSolved(NewSE(in.cfg, pk), c, field); err != nil {
			t.Fatalf("%s: honest order refused: %v", lit.Name, err)
		}
		// The extractor: K = sk R, then the weights from CT.
		ct := toBigs(t, c.CT)
		elems, err := se.Extract(hashes.BLS12381, sk, toBig(t, c.RX), toBig(t, c.RY), ct)
		if err != nil {
			t.Fatal(err)
		}
		got, err := UnpackWeights(in.cfg, elems)
		if err != nil {
			t.Fatal(err)
		}
		for j := range w {
			if got[j] != w[j] {
				t.Fatalf("%s: extracted weight %d is %d, want %d", lit.Name, j, got[j], w[j])
			}
		}
		// (R, CT) of other weights than those the proof is about.
		other, err := AssignSE(in.cfg, pk, in.p, in.ct, []int64{w[0] + 1, w[1]}, in.rhoF, in.sk.S, in.eta, in.ew, rand.Reader)
		if err == nil {
			bad := *c
			bad.RX, bad.RY, bad.CT, bad.Rnd = other.RX, other.RY, other.CT, other.Rnd
			if test.IsSolved(NewSE(in.cfg, pk), &bad, field) == nil {
				t.Fatalf("%s: an encryption of other weights accepted", lit.Name)
			}
		}
	}
}

// TestO2SEFullScale measures the full-scale SE variant of pi_member (opt-in),
// recorded as pi_member_se next to pi_member in results/v8/zk.jsonl.
func TestO2SEFullScale(t *testing.T) {
	if os.Getenv("FAIRHE_ZK_FULL") == "" {
		t.Skip("set FAIRHE_ZK_FULL=1")
	}
	only := os.Getenv("FAIRHE_ZK_PARAMS")
	for _, tc := range []struct {
		lit rlwe.ParamsLiteral
		cl  valclass.Class
		w   []int64
	}{
		{rlwe.Case1BFV(), valclass.BFV(valuation.Cols), valuation.RandomWeights(41, valuation.WMax)},
		{rlwe.Case1CKKS(), valclass.CKKS(valuation.Cols), valuation.RandomWeights(42, valuation.WMaxFixedInt)},
	} {
		if only != "" && only != tc.lit.Name {
			continue
		}
		in := newInstance(t, tc.lit, tc.cl, tc.w)
		_, pk, err := se.KeyGen(hashes.BLS12381, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		var res *zkmeasure.Result
		if os.Getenv("FAIRHE_ZK_PROVE") != "" {
			c, err := AssignSE(in.cfg, pk, in.p, in.ct, in.w, in.rhoF, in.sk.S, in.eta, in.ew, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			res, err = zkmeasure.Measure(ecc.BLS12_381, NewSE(in.cfg, pk), c, "pi_member_se", tc.lit.Name)
			if err != nil {
				t.Fatal(err)
			}
		} else {
			_, res, err = zkmeasure.Compile(ecc.BLS12_381, NewSE(in.cfg, pk), "pi_member_se", tc.lit.Name)
			if err != nil {
				t.Fatal(err)
			}
			res.Note = "compile only"
		}
		res.Note += " SE: " + strconv.Itoa(SEElements(in.cfg)) + " encrypted elements"
		res.FillMemory()
		if err := zkmeasure.Append("zk.jsonl", res); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s/%s: %d constraints, %d public, setup %.1fs, prove %.2fs, verify %.3fs, peak commit %.2f GiB",
			res.Circuit, res.Params, res.Constraints, res.Public, res.SetupS, res.ProveS, res.VerifyS, res.PeakCommitGiB)
	}
}

func toBig(t *testing.T, v frontend.Variable) *big.Int {
	t.Helper()
	switch x := v.(type) {
	case *big.Int:
		return x
	case int64:
		return big.NewInt(x)
	case int:
		return big.NewInt(int64(x))
	}
	t.Fatalf("unexpected assignment type %T", v)
	return nil
}

func toBigs(t *testing.T, vs []frontend.Variable) []*big.Int {
	t.Helper()
	out := make([]*big.Int, len(vs))
	for i, v := range vs {
		out[i] = toBig(t, v)
	}
	return out
}
