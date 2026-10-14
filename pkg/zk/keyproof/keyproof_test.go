package keyproof

// Test B1 (test IDs as in docs/tests.md) for pi_key. A key
// whose uniform component a is not the public coin passes pi_key, which
// takes a as a public input; the verifier's recomputation of a outside the
// circuit rejects it (pkg/market TestB1C3PublicCoins, pkg/rlwe
// TestCase2Path).

import (
	"crypto/rand"
	"math/big"
	"os"
	"testing"

	"fairhe/pkg/hashes"
	"fairhe/pkg/rlwe"
	"fairhe/pkg/zk/gadgets"
	"fairhe/pkg/zk/zkmeasure"

	"github.com/consensys/gnark/test"
)

func smallParams(t testing.TB, lit rlwe.ParamsLiteral) *rlwe.Params {
	lit.LogN, lit.J = 6, 7
	p, err := rlwe.NewParams(lit)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func keyInstance(t testing.TB, p *rlwe.Params) (*rlwe.PublicKey, *rlwe.KeyWitness, []byte) {
	t.Helper()
	a, err := p.CoinPoly(hashes.Case2SlotCoin([]byte("seller"), []byte("com"), 0, hashes.LabelPkA))
	if err != nil {
		t.Fatal(err)
	}
	_, pk, w, err := p.KeyGen(a, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	eta := make([]byte, hashes.SaltBytes)
	rand.Read(eta)
	return pk, w, eta
}

// TestKeyProofSmall (B1): the honest key is accepted on both curves;
// another secret behind the same digest (h_s mismatch), an error outside
// [-19, 19] and a changed b are rejected.
func TestKeyProofSmall(t *testing.T) {
	for _, lit := range []rlwe.ParamsLiteral{rlwe.Case1BFV(), rlwe.Case2BFV(), rlwe.Case2CKKS()} {
		p := smallParams(t, lit)
		cfg := ConfigFor(p)
		pk, w, eta := keyInstance(t, p)
		c, h, err := Assign(cfg, p, pk, w, eta)
		if err != nil {
			t.Fatal(err)
		}
		field := cfg.Curve.ScalarField()
		if err := test.IsSolved(New(cfg), c, field); err != nil {
			t.Fatalf("%s: honest key rejected: %v", lit.Name, err)
		}
		// Another secret: a valid key for s' under the digest of s.
		_, pk2, w2, _ := p.KeyGen(p.Copy(pk.A), rand.Reader)
		c2, _, _ := Assign(cfg, p, pk2, w2, eta)
		c2.H = h
		if test.IsSolved(New(cfg), c2, field) == nil {
			t.Fatalf("%s: another secret accepted under the digest", lit.Name)
		}
		// An error outside the bound with b adjusted to match it.
		w3 := &rlwe.KeyWitness{S: w.S, EPk: append([]int64(nil), w.EPk...)}
		w3.EPk[4] += 40
		b3 := p.Add(pk.B, p.FromSmall(func() []int64 { v := make([]int64, p.N()); v[4] = 40; return v }()))
		c3, _, err := Assign(cfg, p, &rlwe.PublicKey{A: pk.A, B: b3}, w3, eta)
		if err != nil {
			t.Fatal(err)
		}
		if test.IsSolved(New(cfg), c3, field) == nil {
			t.Fatalf("%s: error 40 + e accepted", lit.Name)
		}
		// A changed b with the honest witness.
		c4, _, _ := Assign(cfg, p, pk, w, eta)
		c4.B[1] = new(big.Int).Add(c4.B[1].(*big.Int), big.NewInt(1))
		if test.IsSolved(New(cfg), c4, field) == nil {
			t.Fatalf("%s: changed b accepted", lit.Name)
		}
	}
}

// assignRaw is Assign without the ternary check of the native digest: the
// assignment for any integer secret, with h over s + 1 packed in two bits
// as the circuit computes it.
func assignRaw(t testing.TB, cfg Config, p *rlwe.Params, pk *rlwe.PublicKey, s, e []int64, eta []byte) *Circuit {
	t.Helper()
	a, b := p.ToBig(pk.A), p.ToBig(pk.B)
	L, K, err := gadgets.Quotients(cfg.N, cfg.Q,
		[]gadgets.WTerm{{A: a, B: gadgets.Ints(s)}}, [][]*big.Int{b}, [][]*big.Int{gadgets.Ints(e)})
	if err != nil {
		t.Fatal(err)
	}
	vals := make([]*big.Int, len(s))
	for i, x := range s {
		vals[i] = big.NewInt(x + 1)
	}
	elems, err := hashes.PackBits(cfg.Field(), vals, 2)
	if err != nil {
		t.Fatal(err)
	}
	h, err := hashes.Dig(cfg.Field(), cfg.Label, append(elems, new(big.Int).SetBytes(eta)))
	if err != nil {
		t.Fatal(err)
	}
	c := New(cfg)
	for i := 0; i < cfg.N; i++ {
		c.A[i], c.B[i], c.S[i], c.E[i], c.L[i], c.K[i] = a[i], b[i], s[i], e[i], L[i], K[i]
	}
	c.H, c.Eta = h, new(big.Int).SetBytes(eta)
	return c
}

// TestB1KeyProofBoundaries: each wrong witness breaks one check only, with
// b adjusted to it: an error coefficient of exactly +-20 (while +-19 is
// accepted), and a secret coefficient 2 (while the same construction with
// a ternary coefficient is accepted).
func TestB1KeyProofBoundaries(t *testing.T) {
	for _, lit := range []rlwe.ParamsLiteral{rlwe.Case1BFV(), rlwe.Case2CKKS()} {
		p := smallParams(t, lit)
		cfg := ConfigFor(p)
		field := cfg.Curve.ScalarField()
		pk, w, eta := keyInstance(t, p)
		mono := func(i int, v int64) []int64 {
			m := make([]int64, p.N())
			m[i] = v
			return m
		}
		if err := test.IsSolved(New(cfg), assignRaw(t, cfg, p, pk, w.S, w.EPk, eta), field); err != nil {
			t.Fatalf("%s: honest raw assignment rejected: %v", lit.Name, err)
		}
		for _, v := range []int64{19, -19, 20, -20} {
			e := append([]int64(nil), w.EPk...)
			d := v - e[3]
			e[3] = v
			b := p.Add(pk.B, p.FromSmall(mono(3, d)))
			err := test.IsSolved(New(cfg), assignRaw(t, cfg, p, &rlwe.PublicKey{A: pk.A, B: b}, w.S, e, eta), field)
			if (v == 19 || v == -19) != (err == nil) {
				t.Fatalf("%s: e_pk coefficient %d: accepted = %v", lit.Name, v, err == nil)
			}
		}
		i := 0
		for w.S[i] != 1 {
			i++
		}
		// s_i = 1 -> 2 needs b - a X^i; s_i = 1 -> 0 needs b + a X^i.
		for _, step := range []int64{1, -1} {
			s := append([]int64(nil), w.S...)
			s[i] += step
			b := p.Sub(pk.B, p.MulSmall(pk.A, mono(i, step)))
			err := test.IsSolved(New(cfg), assignRaw(t, cfg, p, &rlwe.PublicKey{A: pk.A, B: b}, s, w.EPk, eta), field)
			if (s[i] == 0) != (err == nil) {
				t.Fatalf("%s: secret coefficient %d: accepted = %v", lit.Name, s[i], err == nil)
			}
		}
	}
}

// TestKeyProofFullScale measures the full-scale key proofs (opt-in).
func TestKeyProofFullScale(t *testing.T) {
	if os.Getenv("FAIRHE_ZK_FULL") == "" {
		t.Skip("set FAIRHE_ZK_FULL=1")
	}
	only := os.Getenv("FAIRHE_ZK_PARAMS")
	prove := os.Getenv("FAIRHE_ZK_PROVE") != ""
	for _, lit := range rlwe.Flagship() {
		if only != "" && only != lit.Name {
			continue
		}
		p := rlwe.MustParams(lit)
		cfg := ConfigFor(p)
		var res *zkmeasure.Result
		var err error
		if prove {
			pk, w, eta := keyInstance(t, p)
			c, _, aerr := Assign(cfg, p, pk, w, eta)
			if aerr != nil {
				t.Fatal(aerr)
			}
			res, err = zkmeasure.Measure(cfg.Curve, New(cfg), c, "pi_key", lit.Name)
		} else {
			_, res, err = zkmeasure.Compile(cfg.Curve, New(cfg), "pi_key", lit.Name)
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
