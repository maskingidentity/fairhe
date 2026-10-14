package evalc2

// Tests B5 and C2 (test IDs as in docs/tests.md) for the
// Case 2 pi_eval: the proof fixes c2,1 by relation (3), so neither a
// monomial K X^(J-l) (the key-recovery order of C2) nor a product by a
// plaintext outside the class passes, and wrong witnesses that each break
// one check fail.

import (
	"crypto/rand"
	"math/big"
	"os"
	"testing"

	"fairhe/pkg/hashes"
	"fairhe/pkg/rlwe"
	"fairhe/pkg/valuation"
	"fairhe/pkg/zk/gadgets"
	"fairhe/pkg/zk/valclass"
	"fairhe/pkg/zk/zkmeasure"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

type instance struct {
	p      *rlwe.Params
	cfg    Config
	c21    []*big.Int
	c11, a []*big.Int
	w      []int64
	rhoF   []byte
	rw     *rlwe.ZeroEncWitness
	slot   *rlwe.Slot
	c2     *rlwe.Ciphertext
	whPoly []int64
}

func newInstance(t testing.TB, lit rlwe.ParamsLiteral, cl valclass.Class, S, w []int64) *instance {
	t.Helper()
	p, err := rlwe.NewParams(lit)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ConfigFor(p, cl)
	if err != nil {
		t.Fatal(err)
	}
	m := cl.M()
	sbar := make([]int64, p.N())
	for k, x := range S {
		sbar[m-1-k] = x
	}
	slot, err := p.PrepareSlot([]byte("seller"), []byte("com"), 0, sbar, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wh := valuation.EncodeForward(cl.Expand(w), p.N())
	c2, rw, err := p.EvalRerand(slot.PK, slot.C1, wh, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rhoF := make([]byte, hashes.SaltBytes)
	rand.Read(rhoF)
	return &instance{p: p, cfg: cfg, c21: p.ToBig(c2.C1), c11: p.ToBig(slot.C1.C1), a: p.ToBig(slot.PK.A),
		w: w, rhoF: rhoF, rw: rw, slot: slot, c2: c2, whPoly: wh}
}

func (in *instance) assign(t testing.TB) *Circuit {
	t.Helper()
	c, err := Assign(in.cfg, in.p, in.c21, in.c11, in.a, in.w, in.rhoF, in.rw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEvalC2Small(t *testing.T) {
	for _, tc := range []struct {
		lit rlwe.ParamsLiteral
		cl  valclass.Class
	}{{rlwe.Case2BFV(), valclass.BFV(2)}, {rlwe.Case2CKKS(), valclass.CKKS(2)}} {
		lit := tc.lit
		lit.LogN, lit.J = 6, tc.cl.M()-1
		S := make([]int64, tc.cl.M())
		for k := range S {
			S[k] = int64(1)<<(tc.cl.XBits-2) + int64(7*k)
		}
		w := []int64{tc.cl.WMax / 2, -tc.cl.WMax}
		in := newInstance(t, lit, tc.cl, S, w)
		field := ecc.BN254.ScalarField()
		if err := test.IsSolved(New(in.cfg), in.assign(t), field); err != nil {
			t.Fatalf("%s: honest order rejected: %v", lit.Name, err)
		}
		// C2: c2,1 = K X^(J-l) with J - l = 3, which would release K s_l
		// through the partial decryption.
		honest := in.assign(t)
		mono := in.assign(t)
		for i := range mono.C21 {
			mono.C21[i] = big.NewInt(0)
		}
		mono.C21[3] = new(big.Int).Lsh(big.NewInt(1), 90)
		mono.L, mono.K = honest.L, honest.K
		if test.IsSolved(New(in.cfg), mono, field) == nil {
			t.Fatalf("%s: c2,1 = K X^l accepted", lit.Name)
		}
		// B5: c2,1 = g c1,1 + a v + e1' for a plaintext g outside the class
		// (a single coordinate), presented with the weights w.
		g := make([]*big.Int, in.p.N())
		for i := range g {
			g[i] = new(big.Int)
		}
		g[lit.J] = big.NewInt(1)
		gc := in.p.Add(in.p.Mul(in.slot.C1.C1, in.p.FromBig(g)), in.p.MulSmall(in.slot.PK.A, in.rw.V))
		gc = in.p.Add(gc, in.p.FromSmall(in.rw.E1))
		sel := in.assign(t)
		for i, x := range in.p.ToBig(gc) {
			sel.C21[i] = x
		}
		if L, K, err := gadgets.Quotients(in.cfg.N, in.cfg.Q,
			[]gadgets.WTerm{{A: in.c11, B: gadgets.Ints(in.cfg.Class.Expand(w))}, {A: in.a, B: gadgets.Ints(in.rw.V)}},
			[][]*big.Int{gadgets.Ints(in.rw.E1)}, [][]*big.Int{in.p.ToBig(gc)}); err == nil {
			for i := range L {
				sel.L[i], sel.K[i] = L[i], K[i]
			}
		}
		if test.IsSolved(New(in.cfg), sel, field) == nil {
			t.Fatalf("%s: c2,1 = g c1,1 + ... with g outside the class accepted", lit.Name)
		}
		// B5: weights above w_max, honestly evaluated.
		out := newInstance(t, lit, tc.cl, S, []int64{tc.cl.WMax + 1, 0})
		if test.IsSolved(New(in.cfg), out.assign(t), field) == nil {
			t.Fatalf("%s: weight above w_max accepted", lit.Name)
		}
	}
}

// TestB5EvalC2Boundaries: a re-randomiser coefficient 2 (while the same
// construction with a ternary coefficient is accepted), an error e1' of
// exactly +-20 (while +-19 is accepted), and Com(f) of other weights; c2,1
// is recomputed for each witness, so relation (3) holds.
func TestB5EvalC2Boundaries(t *testing.T) {
	for _, tc := range []struct {
		lit rlwe.ParamsLiteral
		cl  valclass.Class
	}{{rlwe.Case2BFV(), valclass.BFV(2)}, {rlwe.Case2CKKS(), valclass.CKKS(2)}} {
		lit := tc.lit
		lit.LogN, lit.J = 6, tc.cl.M()-1
		S := make([]int64, tc.cl.M())
		for k := range S {
			S[k] = int64(1)<<(tc.cl.XBits-2) + int64(3*k)
		}
		w := []int64{-tc.cl.WMax / 3, tc.cl.WMax}
		in := newInstance(t, lit, tc.cl, S, w)
		field := ecc.BN254.ScalarField()
		p := in.p
		mono := func(i int, v int64) []int64 {
			m := make([]int64, p.N())
			m[i] = v
			return m
		}
		cp := func() *rlwe.ZeroEncWitness {
			return &rlwe.ZeroEncWitness{V: append([]int64(nil), in.rw.V...), E0: append([]int64(nil), in.rw.E0...),
				E1: append([]int64(nil), in.rw.E1...)}
		}
		solve := func(c21 []*big.Int, rw *rlwe.ZeroEncWitness) error {
			c, err := Assign(in.cfg, p, c21, in.c11, in.a, in.w, in.rhoF, rw)
			if err != nil {
				t.Fatal(err)
			}
			return test.IsSolved(New(in.cfg), c, field)
		}
		i := 0
		for in.rw.V[i] != 1 {
			i++
		}
		for _, step := range []int64{1, -1} {
			rw := cp()
			rw.V[i] += step
			c21 := p.ToBig(p.Add(in.c2.C1, p.MulSmall(in.slot.PK.A, mono(i, step))))
			if err := solve(c21, rw); (rw.V[i] == 0) != (err == nil) {
				t.Fatalf("%s: re-randomiser coefficient %d: accepted = %v", lit.Name, rw.V[i], err == nil)
			}
		}
		for _, v := range []int64{19, -19, 20, -20} {
			rw := cp()
			d := v - rw.E1[3]
			rw.E1[3] = v
			c21 := p.ToBig(p.Add(in.c2.C1, p.FromSmall(mono(3, d))))
			if err := solve(c21, rw); (v == 19 || v == -19) != (err == nil) {
				t.Fatalf("%s: e1' coefficient %d: accepted = %v", lit.Name, v, err == nil)
			}
		}
		c := in.assign(t)
		c.ComF, _ = tc.cl.CommitF(hashes.BN254, []int64{w[0] + 1, w[1]}, in.rhoF)
		if test.IsSolved(New(in.cfg), c, field) == nil {
			t.Fatalf("%s: Com(f) of other weights accepted", lit.Name)
		}
	}
}

// TestEvalC2FullScale measures the full-scale Case 2 pi_eval (opt-in).
func TestEvalC2FullScale(t *testing.T) {
	if os.Getenv("FAIRHE_ZK_FULL") == "" {
		t.Skip("set FAIRHE_ZK_FULL=1")
	}
	only := os.Getenv("FAIRHE_ZK_PARAMS")
	ds := valuation.Generate(61, valuation.NMax)
	for _, tc := range []struct {
		lit rlwe.ParamsLiteral
		cl  valclass.Class
		S   []int64
		w   []int64
	}{
		{rlwe.Case2BFV(), valclass.BFV(valuation.Cols), valuation.Stats(ds), valuation.RandomWeights(62, valuation.WMax)},
		{rlwe.Case2CKKS(), valclass.CKKS(valuation.Cols), valuation.StatsFixed(ds), valuation.RandomWeights(63, valuation.WMaxFixedInt)},
	} {
		if only != "" && only != tc.lit.Name {
			continue
		}
		in := newInstance(t, tc.lit, tc.cl, tc.S, tc.w)
		var res *zkmeasure.Result
		var err error
		if os.Getenv("FAIRHE_ZK_PROVE") != "" {
			res, err = zkmeasure.Measure(ecc.BN254, New(in.cfg), in.assign(t), "pi_eval_c2", tc.lit.Name)
		} else {
			_, res, err = zkmeasure.Compile(ecc.BN254, New(in.cfg), "pi_eval_c2", tc.lit.Name)
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
