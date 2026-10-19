package encproof

// Test B3 (test IDs as in docs/tests.md) for pi_enc: wrong
// witnesses that each break one check.

import (
	"crypto/rand"
	"math/big"
	"os"
	"testing"

	"fairhe/pkg/hashes"
	"fairhe/pkg/rlwe"
	"fairhe/pkg/valuation"
	"fairhe/pkg/zk/valclass"
	"fairhe/pkg/zk/zkmeasure"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

type instance struct {
	p    *rlwe.Params
	cfg  Config
	slot *rlwe.Slot
	S    []int64
	rhoX []byte
}

// newInstance prepares slot 0 for the data S, with Com(x) as the coin input.
func newInstance(t testing.TB, lit rlwe.ParamsLiteral, cl valclass.Class, S []int64) *instance {
	t.Helper()
	p, err := rlwe.NewParams(lit)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ConfigFor(p, cl)
	if err != nil {
		t.Fatal(err)
	}
	rhoX := make([]byte, hashes.SaltBytes)
	rand.Read(rhoX)
	m := cl.M()
	sbar := make([]int64, p.N())
	for k, x := range S {
		sbar[m-1-k] = x
	}
	vals := make([]*big.Int, len(S))
	for k, x := range S {
		vals[k] = big.NewInt(x)
	}
	comX, err := hashes.Commit(hashes.BN254, valclass.LabelX, vals, cl.XBits, rhoX)
	if err != nil {
		// Out-of-range data cannot be committed at XBits; commit at a wider
		// width so that the circuit's range check is what rejects it.
		comX, err = hashes.Commit(hashes.BN254, valclass.LabelX, vals, cl.XBits+8, rhoX)
		if err != nil {
			t.Fatal(err)
		}
	}
	cb := hashes.Bytes32(comX)
	slot, err := p.PrepareSlot([]byte("seller"), cb[:], 0, sbar, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &instance{p: p, cfg: cfg, slot: slot, S: S, rhoX: rhoX}
}

func (in *instance) assign(t testing.TB) *Circuit {
	t.Helper()
	c, err := Assign(in.cfg, in.p, in.slot.C1, in.S, in.rhoX, in.slot.KeyWitness.S, in.slot.Eta, in.slot.EncWitness)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEncProofSmall(t *testing.T) {
	for _, tc := range []struct {
		lit rlwe.ParamsLiteral
		cl  valclass.Class
	}{{rlwe.Case2BFV(), valclass.BFV(2)}, {rlwe.Case2CKKS(), valclass.CKKS(2)}} {
		lit := tc.lit
		lit.LogN, lit.J = 6, tc.cl.M()-1
		m := tc.cl.M()
		S := make([]int64, m)
		for k := range S {
			S[k] = tc.cl.XTop().Int64() - int64(k)
		}
		in := newInstance(t, lit, tc.cl, S)
		field := ecc.BN254.ScalarField()
		if err := test.IsSolved(New(in.cfg), in.assign(t), field); err != nil {
			t.Fatalf("%s: honest slot rejected: %v", lit.Name, err)
		}
		// B3: data outside the agreed input range, honestly encrypted.
		big := append([]int64(nil), S...)
		big[2] = int64(1) << tc.cl.XBits
		out := newInstance(t, lit, tc.cl, big)
		// The prover's best attempt commits at a wider width; the circuit of
		// the class checks XBits.
		wide := out.cfg
		wide.Class.XBits += 8
		outC, err := Assign(wide, out.p, out.slot.C1, out.S, out.rhoX, out.slot.KeyWitness.S, out.slot.Eta, out.slot.EncWitness)
		if err != nil {
			t.Fatal(err)
		}
		if test.IsSolved(New(in.cfg), outC, field) == nil {
			t.Fatalf("%s: out-of-range data accepted", lit.Name)
		}
		// A data ciphertext with oversized noise K X^l (the Case 2 analogue of
		// C1: the seller's c1 must be fresh).
		const K, l = int64(1) << 30, 1
		noisy := *in
		ew := &rlwe.EncWitness{E: append([]int64(nil), in.slot.EncWitness.E...)}
		ew.E[l] += K
		mono := make([]int64, in.p.N())
		mono[l] = K
		c1 := &rlwe.Ciphertext{C0: in.p.Add(in.slot.C1.C0, in.p.FromSmall(mono)), C1: in.slot.C1.C1}
		noisy.slot = &rlwe.Slot{Index: in.slot.Index, SK: in.slot.SK, PK: in.slot.PK, C1: c1,
			Eta: in.slot.Eta, HS: in.slot.HS, KeyWitness: in.slot.KeyWitness, EncWitness: ew}
		if test.IsSolved(New(in.cfg), noisy.assign(t), field) == nil {
			t.Fatalf("%s: noisy data ciphertext accepted", lit.Name)
		}
	}
}

// TestB3EncProofBoundaries: an encryption noise coefficient of exactly
// +-20 (while +-19 is accepted), Com(x) of other data, h_s of another
// secret, and in the fixed-point class a data entry of 2^20 + 1 (while 2^20
// is accepted).
func TestB3EncProofBoundaries(t *testing.T) {
	for _, tc := range []struct {
		lit rlwe.ParamsLiteral
		cl  valclass.Class
	}{{rlwe.Case2BFV(), valclass.BFV(2)}, {rlwe.Case2CKKS(), valclass.CKKS(2)}} {
		lit := tc.lit
		lit.LogN, lit.J = 6, tc.cl.M()-1
		S := make([]int64, tc.cl.M())
		for k := range S {
			S[k] = int64(1)<<(tc.cl.XBits-2) + int64(5*k)
		}
		in := newInstance(t, lit, tc.cl, S)
		field := ecc.BN254.ScalarField()
		const l = 2
		for _, v := range []int64{19, -19, 20, -20} {
			ew := &rlwe.EncWitness{E: append([]int64(nil), in.slot.EncWitness.E...)}
			d := v - ew.E[l]
			ew.E[l] = v
			mono := make([]int64, in.p.N())
			mono[l] = d
			c1 := &rlwe.Ciphertext{C0: in.p.Add(in.slot.C1.C0, in.p.FromSmall(mono)), C1: in.slot.C1.C1}
			c, err := Assign(in.cfg, in.p, c1, in.S, in.rhoX, in.slot.KeyWitness.S, in.slot.Eta, ew)
			if err != nil {
				t.Fatal(err)
			}
			err = test.IsSolved(New(in.cfg), c, field)
			if (v == 19 || v == -19) != (err == nil) {
				t.Fatalf("%s: noise coefficient %d: accepted = %v", lit.Name, v, err == nil)
			}
		}
		// Com(x) of other data than the encrypted S.
		c := in.assign(t)
		other := append([]int64(nil), S...)
		other[0]++
		c.ComX, _ = tc.cl.CommitX(hashes.BN254, other, in.rhoX)
		if test.IsSolved(New(in.cfg), c, field) == nil {
			t.Fatalf("%s: Com(x) of other data accepted", lit.Name)
		}
		// h_s of another slot's secret.
		c = in.assign(t)
		c.HS = newInstance(t, lit, tc.cl, S).slot.HS
		if test.IsSolved(New(in.cfg), c, field) == nil {
			t.Fatalf("%s: h_s of another secret accepted", lit.Name)
		}
		// The data range of the fixed-point class: an entry of 2^20 is
		// accepted and 2^20 + 1, which fits the 21 bits of Com(x), is refused.
		if tc.cl.XMax > 0 {
			for _, d := range []int64{0, 1} {
				edge := append([]int64(nil), S...)
				edge[1] = tc.cl.XMax + d
				err := test.IsSolved(New(in.cfg), newInstance(t, lit, tc.cl, edge).assign(t), field)
				if (d == 0) != (err == nil) {
					t.Fatalf("%s: data entry %d: accepted = %v", lit.Name, edge[1], err == nil)
				}
			}
		}
	}
}

// TestEncProofFullScale measures the full-scale pi_enc (opt-in).
func TestEncProofFullScale(t *testing.T) {
	if os.Getenv("FAIRHE_ZK_FULL") == "" {
		t.Skip("set FAIRHE_ZK_FULL=1")
	}
	only := os.Getenv("FAIRHE_ZK_PARAMS")
	ds := valuation.Generate(51, valuation.NMax)
	for _, tc := range []struct {
		lit rlwe.ParamsLiteral
		cl  valclass.Class
		S   []int64
	}{
		{rlwe.Case2BFV(), valclass.BFV(valuation.Cols), valuation.Stats(ds)},
		{rlwe.Case2CKKS(), valclass.CKKS(valuation.Cols), valuation.StatsFixed(ds)},
	} {
		if only != "" && only != tc.lit.Name {
			continue
		}
		in := newInstance(t, tc.lit, tc.cl, tc.S)
		var res *zkmeasure.Result
		var err error
		if os.Getenv("FAIRHE_ZK_PROVE") != "" {
			res, err = zkmeasure.Measure(ecc.BN254, New(in.cfg), in.assign(t), "pi_enc", tc.lit.Name)
		} else {
			_, res, err = zkmeasure.Compile(ecc.BN254, New(in.cfg), "pi_enc", tc.lit.Name)
			if res != nil {
				res.Note = "compile only"
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		res.FillMemory()
		if err := zkmeasure.Append("zk.jsonl", res); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s/%s: %d constraints, %d public, %d commitment(s), setup %.1fs, prove %.1fs, verify %.3fs, peak commit %.2f GiB",
			res.Circuit, res.Params, res.Constraints, res.Public, res.Commitments, res.SetupS, res.ProveS, res.VerifyS, res.PeakCommitGiB)
	}
}
