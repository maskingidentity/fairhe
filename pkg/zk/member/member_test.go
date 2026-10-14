package member

// Tests B2 and C1 (test IDs as in docs/tests.md) for
// pi_member: wrong witnesses that each break one check, and the Case 1
// noise attack (an order whose noise is K X^l).

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
	ct     *rlwe.Ciphertext
	w      []int64
	rhoF   []byte
	sk     *rlwe.SecretKey
	eta    []byte
	ew     *rlwe.EncWitness
	encMsg []int64
}

func newInstance(t testing.TB, lit rlwe.ParamsLiteral, cl valclass.Class, w []int64) *instance {
	t.Helper()
	p, err := rlwe.NewParams(lit)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ConfigFor(p, cl)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := p.CoinPoly(hashes.Case1KeyCoin([]byte("buyer"), 0, hashes.LabelPkA))
	sk, _, _, err := p.KeyGen(a, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a1, _ := p.FreshUniform(rand.Reader)
	msg := cl.Expand(w)
	ct, ew, err := p.EncryptSK(sk, msg, a1, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rhoF, eta := make([]byte, hashes.SaltBytes), make([]byte, hashes.SaltBytes)
	rand.Read(rhoF)
	rand.Read(eta)
	return &instance{p: p, cfg: cfg, ct: ct, w: w, rhoF: rhoF, sk: sk, eta: eta, ew: ew, encMsg: msg}
}

func (in *instance) assign(t testing.TB) *Circuit {
	t.Helper()
	c, err := Assign(in.cfg, in.p, in.ct, in.w, in.rhoF, in.sk.S, in.eta, in.ew)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestMemberSmall(t *testing.T) {
	for _, tc := range []struct {
		lit rlwe.ParamsLiteral
		cl  valclass.Class
	}{{rlwe.Case1BFV(), valclass.BFV(2)}, {rlwe.Case1CKKS(), valclass.CKKS(2)}} {
		lit := tc.lit
		lit.LogN, lit.J = 6, tc.cl.M()-1
		w := []int64{-tc.cl.WMax, tc.cl.WMax / 3}
		in := newInstance(t, lit, tc.cl, w)
		field := ecc.BLS12_381.ScalarField()
		if err := test.IsSolved(New(in.cfg), in.assign(t), field); err != nil {
			t.Fatalf("%s: honest order rejected: %v", lit.Name, err)
		}
		// C1: a ciphertext with noise e_c = K X^l decrypts to the same w_hat
		// up to K at coefficient l: the noise channel of paper Section 3.3.1.
		const K, l = int64(1) << 30, 3
		bad := *in
		bad.ew = &rlwe.EncWitness{E: append([]int64(nil), in.ew.E...)}
		bad.ew.E[l] += K
		mono := make([]int64, in.p.N())
		mono[l] = K
		bad.ct = &rlwe.Ciphertext{C0: in.p.Add(in.ct.C0, in.p.FromSmall(mono)), C1: in.ct.C1}
		if test.IsSolved(New(in.cfg), bad.assign(t), field) == nil {
			t.Fatalf("%s: ciphertext with noise K X^l accepted", lit.Name)
		}
		// B2: a valid order under another secret, presented under the
		// registered h_sB.
		other := newInstance(t, lit, tc.cl, w)
		c := other.assign(t)
		c.HSB = in.assign(t).HSB
		if test.IsSolved(New(in.cfg), c, field) == nil {
			t.Fatalf("%s: another secret accepted under h_sB", lit.Name)
		}
		// B2: weights outside the class, honestly encrypted.
		out := newInstance(t, lit, tc.cl, []int64{tc.cl.WMax + 1, 0})
		if test.IsSolved(New(in.cfg), out.assign(t), field) == nil {
			t.Fatalf("%s: weight above w_max accepted", lit.Name)
		}
	}
}

// assignNoise is the assignment a prover must use for the ciphertext ct
// with the instance's weights, secret and commitment: the noise E, of any
// size, closes the encryption relation, and the quotients follow.
func (in *instance) assignNoise(t testing.TB, ct *rlwe.Ciphertext, E []*big.Int) *Circuit {
	t.Helper()
	cfg, p := in.cfg, in.p
	c0, c1 := p.ToBig(ct.C0), p.ToBig(ct.C1)
	msg := make([]*big.Int, cfg.N)
	for i := range msg {
		msg[i] = new(big.Int)
	}
	for k, x := range cfg.Class.Expand(in.w) {
		msg[k].Mul(cfg.KEnc, big.NewInt(x))
	}
	L, K, err := gadgets.Quotients(cfg.N, cfg.Q, []gadgets.WTerm{{A: c1, B: gadgets.Ints(in.sk.S)}},
		[][]*big.Int{c0}, [][]*big.Int{E, msg})
	if err != nil {
		t.Fatal(err)
	}
	c := in.assign(t)
	for i := 0; i < cfg.N; i++ {
		c.C0[i], c.C1[i], c.E[i], c.L[i], c.K[i] = c0[i], c1[i], E[i], L[i], K[i]
	}
	return c
}

// TestB2MemberBoundaries: an encryption noise coefficient of exactly +-20
// (while +-19 is accepted), a ciphertext of a w_hat that is not the
// expansion of w (here w_hat plus a unit vector, which would read one
// statistic), and Com(f) of other weights.
func TestB2MemberBoundaries(t *testing.T) {
	for _, tc := range []struct {
		lit rlwe.ParamsLiteral
		cl  valclass.Class
	}{{rlwe.Case1BFV(), valclass.BFV(2)}, {rlwe.Case1CKKS(), valclass.CKKS(2)}} {
		lit := tc.lit
		lit.LogN, lit.J = 6, tc.cl.M()-1
		w := []int64{tc.cl.WMax / 2, -tc.cl.WMax / 5}
		in := newInstance(t, lit, tc.cl, w)
		field := ecc.BLS12_381.ScalarField()
		const l = 4
		for _, v := range []int64{19, -19, 20, -20} {
			e := append([]int64(nil), in.ew.E...)
			d := v - e[l]
			e[l] = v
			mono := make([]int64, in.p.N())
			mono[l] = d
			bad := *in
			bad.ct = &rlwe.Ciphertext{C0: in.p.Add(in.ct.C0, in.p.FromSmall(mono)), C1: in.ct.C1}
			bad.ew = &rlwe.EncWitness{E: e}
			err := test.IsSolved(New(in.cfg), bad.assign(t), field)
			if (v == 19 || v == -19) != (err == nil) {
				t.Fatalf("%s: noise coefficient %d: accepted = %v", lit.Name, v, err == nil)
			}
		}
		// The ciphertext of w_hat + X^2: the noise that closes the relation
		// for w carries K_enc at coefficient 2.
		msg := append([]int64(nil), in.encMsg...)
		msg[2]++
		a1, _ := in.p.FreshUniform(rand.Reader)
		ct, ew, err := in.p.EncryptSK(in.sk, msg, a1, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		E := gadgets.Ints(ew.E)
		E[2] = new(big.Int).Add(E[2], in.cfg.KEnc)
		if test.IsSolved(New(in.cfg), in.assignNoise(t, ct, E), field) == nil {
			t.Fatalf("%s: a w_hat that is not the expansion of w accepted", lit.Name)
		}
		// Control: the same construction for the honest ciphertext passes.
		if err := test.IsSolved(New(in.cfg), in.assignNoise(t, in.ct, gadgets.Ints(in.ew.E)), field); err != nil {
			t.Fatalf("%s: honest assignment through assignNoise rejected: %v", lit.Name, err)
		}
		// Com(f) of other weights.
		c := in.assign(t)
		other, _ := tc.cl.CommitF(hashes.BLS12381, []int64{w[0] + 1, w[1]}, in.rhoF)
		c.ComF = other
		if test.IsSolved(New(in.cfg), c, field) == nil {
			t.Fatalf("%s: Com(f) of other weights accepted", lit.Name)
		}
	}
}

// TestMemberFullScale measures the full-scale pi_member (opt-in).
func TestMemberFullScale(t *testing.T) {
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
		var res *zkmeasure.Result
		var err error
		if os.Getenv("FAIRHE_ZK_PROVE") != "" {
			res, err = zkmeasure.Measure(ecc.BLS12_381, New(in.cfg), in.assign(t), "pi_member", tc.lit.Name)
		} else {
			_, res, err = zkmeasure.Compile(ecc.BLS12_381, New(in.cfg), "pi_member", tc.lit.Name)
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
