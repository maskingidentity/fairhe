package rlwe_test

// Tests of the HE layer, numbered as in docs/tests.md where it lists them:
// A6 (the margins of the actual chains), G2 (the flood sampler); A1-A5 over
// 1,000 inputs are in accuracy_test.go. The path tests below run each case
// once on a random and a worst-case input with the relations of the proofs.

import (
	"crypto/rand"
	"encoding/hex"
	"math"
	"math/big"
	"testing"

	"fairhe/pkg/hashes"
	"fairhe/pkg/rlwe"
	"fairhe/pkg/valuation"
)

func params(t *testing.T, lit rlwe.ParamsLiteral) *rlwe.Params {
	t.Helper()
	p, err := rlwe.NewParams(lit)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// classBounds returns the class bounds of the running example for a set.
func classBounds(p *rlwe.Params) rlwe.ClassBounds {
	switch {
	case p.Case() == rlwe.Case1 && p.Scheme() == rlwe.BFV:
		return rlwe.ClassBounds{PtNormL1: valuation.SNormL1MaxInt(), FMax: new(big.Rat).SetInt(valuation.FMaxInt())}
	case p.Case() == rlwe.Case1:
		return rlwe.ClassBounds{PtNormL1: valuation.SNormL1MaxFixed(), FMax: valuation.FMaxFixed()}
	case p.Scheme() == rlwe.BFV:
		return rlwe.ClassBounds{PtNormL1: valuation.WHatNormL1MaxInt(), FMax: new(big.Rat).SetInt(valuation.FMaxInt())}
	default:
		return rlwe.ClassBounds{PtNormL1: valuation.WHatNormL1MaxFixed(), FMax: valuation.FMaxFixed()}
	}
}

// TestFlagshipChains checks the explicit chains: sizes, the released
// coefficient of the running example, and the CKKS Case 1 delivery modulus
// as the first prime.
func TestFlagshipChains(t *testing.T) {
	wantLogQ := map[string]float64{"case1_bfv": 134, "case1_ckks": 103, "case2_bfv": 125, "case2_ckks": 111}
	for _, lit := range rlwe.Flagship() {
		p := params(t, lit)
		if p.J() != valuation.J || p.N() != 8192 {
			t.Fatalf("%s: J = %d, N = %d", lit.Name, p.J(), p.N())
		}
		if l := p.LogQ(); l >= wantLogQ[lit.Name] || l < wantLogQ[lit.Name]-0.001 {
			t.Fatalf("%s: log2 Q = %.8f, want just below %v", lit.Name, l, wantLogQ[lit.Name])
		}
	}
	c1 := params(t, rlwe.Case1CKKS())
	if c1.QDel().Uint64() != c1.Literal().Q[0] {
		t.Fatal("case1_ckks: q_del is not the first prime of the chain")
	}
}

// TestA6Margins checks every margin of the four actual chains against the
// class bounds (A6; scripts/check_margins_v8.py repeats it from
// params.jsonl): the flood widths of Table 2 are exactly the required ones,
// the decoding conditions and tolerances hold, and the margins of Appendix
// C.4 are kept.
func TestA6Margins(t *testing.T) {
	wantLogB := map[string]float64{"case1_bfv": 39.3, "case1_ckks": 33.3, "case2_bfv": 30.2, "case2_ckks": 42.2}
	for _, lit := range rlwe.Flagship() {
		p := params(t, lit)
		rep := p.CheckMargins(classBounds(p))
		t.Logf("%-10s log2Q=%.8f log2qdel=%.6f log2B=%.3f sigma=%d/%d decode=%.6f log2tau=%.4f headroom=2^%.2f",
			rep.Name, rep.LogQ, rep.LogQDel, rep.LogB, rep.SigmaFl, rep.SigmaRequired, rep.DecodeTerm, rep.LogTau, rep.LogWrapHeadroom)
		if !rep.OK() {
			t.Fatalf("%s: %v", lit.Name, rep.Failures)
		}
		if rep.SigmaRequired != lit.SigmaFl {
			t.Errorf("%s: required sigma %d, Table 2 has %d", lit.Name, rep.SigmaRequired, lit.SigmaFl)
		}
		if math.Abs(rep.LogB-wantLogB[lit.Name]) > 0.05 {
			t.Errorf("%s: log2 B = %.3f, Table 2 has %.1f", lit.Name, rep.LogB, wantLogB[lit.Name])
		}
	}
	// The margins bite: one bit less of flood, or a chain without its last
	// prime, must fail.
	for _, lit := range rlwe.Flagship() {
		short := lit
		short.SigmaFl--
		if params(t, short).CheckMargins(classBounds(params(t, lit))).OK() {
			t.Errorf("%s: sigma_fl - 1 passes", lit.Name)
		}
		cut := lit
		cut.Q = append([]uint64(nil), lit.Q[:len(lit.Q)-1]...)
		if lit.Case == rlwe.Case1 && lit.Scheme == rlwe.CKKS {
			continue // q_del is the remaining prime: Q = q_del is not a valid set
		}
		if pc, err := rlwe.NewParams(cut); err == nil && pc.CheckMargins(classBounds(pc)).OK() {
			t.Errorf("%s: a chain without its last prime passes", lit.Name)
		}
	}
}

// TestKeyGenF14 checks the key generation: ternary secret, errors in
// [-19, 19], the public coin recomputed bit-exactly from H_coin, and the
// key relation through the independent checker.
func TestKeyGenF14(t *testing.T) {
	p := params(t, rlwe.Case1BFV())
	seed := hashes.Case1KeyCoin([]byte("buyer-1"), 0, hashes.LabelPkA)
	a, err := p.CoinPoly(seed)
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := p.CoinPoly(seed)
	if !p.RingQ().Equal(a, a2) {
		t.Fatal("public coin is not reproducible")
	}
	// Known answer: the first coefficient of each limb pins the expansion
	// H_coin -> KeyedPRNG -> uniform sampler of Lattigo v6.1.1.
	kat := hex.EncodeToString(big.NewInt(0).SetUint64(a.Coeffs[0][0]).Bytes()) + "/" +
		hex.EncodeToString(big.NewInt(0).SetUint64(a.Coeffs[1][0]).Bytes()) + "/" +
		hex.EncodeToString(big.NewInt(0).SetUint64(a.Coeffs[2][0]).Bytes())
	const wantKAT = "0665f5d396e1/1655667e6135/0272ac341744"
	if kat != wantKAT {
		t.Errorf("public-coin KAT: got %s", kat)
	}
	sk, pk, w, err := p.KeyGen(a, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.CheckKey(pk, w); err != nil {
		t.Fatal(err)
	}
	counts := map[int64]int{}
	for _, x := range sk.S {
		counts[x]++
	}
	for v := int64(-1); v <= 1; v++ {
		if c := counts[v]; c < 2400 || c > 3060 {
			t.Errorf("ternary value %d drawn %d times out of 8192", v, c)
		}
	}
	// A tampered key fails the relation.
	bad := *w
	bad.EPk = append([]int64(nil), w.EPk...)
	bad.EPk[3] += 20
	if p.CheckKey(pk, &bad) == nil {
		t.Fatal("CheckKey accepts e_pk out of range")
	}
}

// TestGaussianTruncationF14 draws many errors and checks the truncation at
// B_err = 19 and the standard deviation 3.2.
func TestGaussianTruncationF14(t *testing.T) {
	p := params(t, rlwe.Case2BFV())
	var sum, sq float64
	n := 0
	maxAbs := int64(0)
	for r := 0; r < 64; r++ {
		e, err := p.SampleError(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range e {
			if x > 19 || x < -19 {
				t.Fatalf("error %d outside [-19, 19]", x)
			}
			if x > maxAbs {
				maxAbs = x
			} else if -x > maxAbs {
				maxAbs = -x
			}
			sum += float64(x)
			sq += float64(x * x)
			n++
		}
	}
	mean := sum / float64(n)
	sd := math.Sqrt(sq/float64(n) - mean*mean)
	if math.Abs(mean) > 0.05 || math.Abs(sd-3.2) > 0.05 {
		t.Fatalf("error mean %.4f, sd %.4f over %d draws", mean, sd, n)
	}
	t.Logf("%d draws: mean %.4f, sd %.4f, max |e| %d", n, mean, sd, maxAbs)
}

// TestG2FloodSampler checks the big-integer flood (G2): the closed
// interval [-2^sigma, 2^sigma], both endpoints reachable at small widths,
// near-uniform counts, and the widths of Table 2.
func TestG2FloodSampler(t *testing.T) {
	small := rlwe.Case2BFV()
	small.SigmaFl = 2 // values -4 .. 4
	p := params(t, small)
	counts := map[int64]int{}
	const draws = 90000
	for i := 0; i < draws; i++ {
		v, err := p.SampleFlood(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if !v.IsInt64() || v.Int64() < -4 || v.Int64() > 4 {
			t.Fatalf("flood %s outside [-4, 4]", v)
		}
		counts[v.Int64()]++
	}
	for v := int64(-4); v <= 4; v++ {
		if c := counts[v]; c < 9400 || c > 10600 { // expected 10000 each
			t.Errorf("value %d drawn %d times of %d", v, c, draws)
		}
	}
	for _, lit := range rlwe.Flagship() {
		p := params(t, lit)
		bound := new(big.Int).Lsh(big.NewInt(1), uint(lit.SigmaFl))
		neg, top := 0, 0
		for i := 0; i < 2000; i++ {
			v, err := p.SampleFlood(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if new(big.Int).Abs(v).Cmp(bound) > 0 {
				t.Fatalf("%s: flood beyond 2^%d", lit.Name, lit.SigmaFl)
			}
			if v.Sign() < 0 {
				neg++
			}
			if new(big.Int).Abs(v).BitLen() == lit.SigmaFl {
				top++ // |v| in [2^(sigma-1), 2^sigma): about half of the draws
			}
		}
		if neg < 850 || neg > 1150 || top < 850 || top > 1150 {
			t.Errorf("%s: %d negative and %d top-bit draws of 2000", lit.Name, neg, top)
		}
	}
}

// TestEncryptProductF15 checks the secret-key encryption and the integer
// product with centred operands: the raw decryption of the product
// at coefficient 527 is K_enc <w_hat, S> + (e S_bar)_527 exactly, with
// negative coefficients and without wrap-around.
func TestEncryptProductF15(t *testing.T) {
	p := params(t, rlwe.Case1BFV())
	ds, w := valuation.Generate(11, 700), valuation.RandomWeights(12, valuation.WMax)
	wh, S := valuation.ExpandWeights(w), valuation.Stats(ds)
	a, _ := p.CoinPoly(hashes.Case1KeyCoin([]byte("b"), 0, hashes.LabelPkA))
	sk, _, _, err := p.KeyGen(a, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a1, _ := p.FreshUniform(rand.Reader)
	c, ew, err := p.EncryptSK(sk, valuation.EncodeForward(wh, p.N()), a1, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.CheckEnc(c, valuation.EncodeForward(wh, p.N()), sk.S, ew); err != nil {
		t.Fatal(err)
	}
	sBar := valuation.EncodeReversed(S, p.N())
	prod, err := p.MulPlain(c, sBar)
	if err != nil {
		t.Fatal(err)
	}
	raw := p.RawDecrypt(sk, prod)[valuation.J]
	f := valuation.F(ds, w)
	want := new(big.Int).Mul(p.EncScale(), f)
	eS := int64(0)
	for k := 0; k < valuation.M; k++ { // (e S_bar)_527 = sum_k e_k S_k (no wrap)
		eS += ew.E[k] * S[k]
	}
	want.Add(want, big.NewInt(eS)).Mod(want, p.Q())
	if raw.Cmp(want) != 0 {
		t.Fatalf("raw decryption at 527 is not Delta f + (e S_bar)_527")
	}
	if got := p.DecodeBFV(raw, p.Q()); got.Cmp(f) != 0 {
		t.Fatalf("decoded %s, f = %s", got, f)
	}
}

// case1Run executes the Case 1 path end to end and returns the decoded
// value and the tolerance check.
type case1Data struct {
	name   string
	ds     *valuation.Dataset
	w      valuation.Weights
	encMsg []int64 // w_hat (forward)
	ptMsg  []int64 // S_bar (reversed)
	fInt   *big.Int
	fFixed *big.Rat
}

func case1Inputs(p *rlwe.Params) []case1Data {
	type src struct {
		name string
		ds   *valuation.Dataset
		seed uint64
		max  int64
		wc   bool
	}
	srcs := []src{{"random", valuation.Generate(21, 600), 22, 0, false}, {"worst case", valuation.WorstCase(), 0, 0, true}}
	var out []case1Data
	for _, s := range srcs {
		d := case1Data{name: s.name, ds: s.ds}
		if p.Scheme() == rlwe.BFV {
			if s.wc {
				d.w = valuation.WorstWeights(valuation.WMax)
			} else {
				d.w = valuation.RandomWeights(s.seed, valuation.WMax)
			}
			d.encMsg = valuation.EncodeForward(valuation.ExpandWeights(d.w), p.N())
			d.ptMsg = valuation.EncodeReversed(valuation.Stats(s.ds), p.N())
			d.fInt = valuation.F(s.ds, d.w)
		} else {
			if s.wc {
				d.w = valuation.WorstWeights(valuation.WMaxFixedInt)
			} else {
				d.w = valuation.RandomWeights(s.seed, valuation.WMaxFixedInt)
			}
			S := valuation.StatsFixed(s.ds)
			d.encMsg = valuation.EncodeForward(valuation.ExpandWeightsFixed(d.w), p.N())
			d.ptMsg = valuation.EncodeReversed(S, p.N())
			d.fFixed = valuation.FFixed(S, d.w)
		}
		out = append(out, d)
	}
	return out
}

// TestCase1Path runs the Case 1 path: the buyer's key from public
// coins and its secret-key encryption of w_hat, the seller's product by
// S_bar, sanitisation, extraction and switch to q_del, and the buyer's
// decoding, exact for BFV and within tau for CKKS, on a random and the
// worst-case input; and the pi_eval relation through the checker.
func TestCase1Path(t *testing.T) {
	for _, lit := range []rlwe.ParamsLiteral{rlwe.Case1BFV(), rlwe.Case1CKKS()} {
		p := params(t, lit)
		rep := p.CheckMargins(classBounds(p))
		for _, d := range case1Inputs(p) {
			a, _ := p.CoinPoly(hashes.Case1KeyCoin([]byte("buyer"), 7, hashes.LabelPkA))
			sk, pk, _, err := p.KeyGen(a, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			a1, _ := p.FreshUniform(rand.Reader)
			c, _, err := p.EncryptSK(sk, d.encMsg, a1, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			prod, err := p.MulPlain(c, d.ptMsg)
			if err != nil {
				t.Fatal(err)
			}
			san, sw, err := p.Sanitize(pk, prod, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			D, xw, err := p.ExtractSwitch(san)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.CheckCase1Eval(c, pk, d.ptMsg, sw, D, xw); err != nil {
				t.Fatalf("%s/%s: %v", lit.Name, d.name, err)
			}
			if p.Scheme() == rlwe.BFV {
				if got := p.DecodeDeliverableBFV(sk, D); got.Cmp(d.fInt) != 0 {
					t.Fatalf("%s/%s: decoded %s, f = %s", lit.Name, d.name, got, d.fInt)
				}
			} else {
				got := p.DecodeDeliverableCKKS(sk, D)
				diff, _ := new(big.Rat).Sub(got, d.fFixed).Float64()
				if math.Log2(math.Abs(diff)) > rep.LogTau {
					t.Fatalf("%s/%s: error 2^%.2f above tau 2^%.2f", lit.Name, d.name, math.Log2(math.Abs(diff)), rep.LogTau)
				}
				ff, _ := d.fFixed.Float64()
				t.Logf("%s/%s: f = %.6f, |error| = %.3g (tau = 2^%.2f)", lit.Name, d.name, ff, math.Abs(diff), rep.LogTau)
			}
			// Tampering with the flood beyond its bound, or with a rounding
			// remainder, breaks the relation.
			badFl := *sw
			badFl.EFl = new(big.Int).Lsh(big.NewInt(1), uint(lit.SigmaFl+1))
			if p.CheckCase1Eval(c, pk, d.ptMsg, &badFl, D, xw) == nil {
				t.Fatalf("%s: checker accepts an oversized flood", lit.Name)
			}
			badSw := *xw
			badSw.R1 = append([]*big.Int(nil), xw.R1...)
			badSw.R1[5] = new(big.Int).Add(xw.R1[5], big.NewInt(1))
			if p.CheckCase1Eval(c, pk, d.ptMsg, sw, D, &badSw) == nil {
				t.Fatalf("%s: checker accepts a wrong rounding remainder", lit.Name)
			}
		}
	}
}

// TestCase1CKKSSwitchCrossCheck checks that the switch to the first prime
// equals Lattigo's rounded division by the last prime.
func TestCase1CKKSSwitchCrossCheck(t *testing.T) {
	p := params(t, rlwe.Case1CKKS())
	x, _ := p.FreshUniform(rand.Reader)
	ct := &rlwe.Ciphertext{C0: x, C1: p.Copy(x)}
	D, _, err := p.ExtractSwitch(ct)
	if err != nil {
		t.Fatal(err)
	}
	in := p.Copy(x)
	out := p.RingQ().AtLevel(0).NewPoly()
	p.RingQ().DivRoundByLastModulus(in, out)
	for i := 0; i < p.N(); i++ {
		if D.D1[i].Uint64() != out.Coeffs[0][i] {
			t.Fatalf("coefficient %d: switch %s, Lattigo %d", i, D.D1[i], out.Coeffs[0][i])
		}
	}
}

// TestCase2Path runs the Case 2 path: slot preparation with public
// coins bound to (id_S, Com(x), i), the buyer's recomputation of the coins
// (B1: a slot of another index fails), evaluation and re-randomisation, the
// single partial decryption, and the buyer's decoding, exact for BFV and
// within tau for CKKS, with the relations of pi_key, pi_enc, pi_eval and
// pi_dec through the checker.
func TestCase2Path(t *testing.T) {
	for _, lit := range []rlwe.ParamsLiteral{rlwe.Case2BFV(), rlwe.Case2CKKS()} {
		p := params(t, lit)
		rep := p.CheckMargins(classBounds(p))
		for _, d := range case1Inputs(p) { // same inputs, roles swapped
			// Seller: Com(x) over the statistics, then the slot.
			field := hashes.BN254
			S := valuation.Stats(d.ds)
			bits := 26
			if p.Scheme() == rlwe.CKKS {
				S = valuation.StatsFixed(d.ds)
				bits = valuation.FracBits + 1
			}
			vals := make([]*big.Int, len(S))
			for i, v := range S {
				vals[i] = big.NewInt(v)
			}
			rho := make([]byte, hashes.SaltBytes)
			rand.Read(rho)
			comX, err := hashes.Commit(field, "x", vals, bits, rho)
			if err != nil {
				t.Fatal(err)
			}
			comXB := hashes.Bytes32(comX)
			slot, err := p.PrepareSlot([]byte("seller"), comXB[:], 2, valuation.EncodeReversed(S, p.N()), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.CheckKey(slot.PK, slot.KeyWitness); err != nil {
				t.Fatal(err)
			}
			if err := p.CheckEnc(slot.C1, valuation.EncodeReversed(S, p.N()), slot.KeyWitness.S, slot.EncWitness); err != nil {
				t.Fatal(err)
			}
			// Buyer: the uniform components must equal the public coins.
			if err := p.CheckSlotCoins([]byte("seller"), comXB[:], 2, slot.PK, slot.C1); err != nil {
				t.Fatal(err)
			}
			if p.CheckSlotCoins([]byte("seller"), comXB[:], 3, slot.PK, slot.C1) == nil {
				t.Fatal("coins of slot 2 pass as slot 3")
			}
			wh := valuation.ExpandWeights(d.w)
			if p.Scheme() == rlwe.CKKS {
				wh = valuation.ExpandWeightsFixed(d.w)
			}
			whPoly := valuation.EncodeForward(wh, p.N())
			c2, rw, err := p.EvalRerand(slot.PK, slot.C1, whPoly, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.CheckCase2Eval(c2.C1, slot.C1.C1, slot.PK, whPoly, rw); err != nil {
				t.Fatal(err)
			}
			// Seller: one partial decryption per slot.
			pd, efl, err := slot.PartialDecryptOnce(p, c2.C1, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.CheckPDec(c2.C1, slot.KeyWitness.S, pd, efl); err != nil {
				t.Fatal(err)
			}
			if _, _, err := slot.PartialDecryptOnce(p, c2.C1, rand.Reader); err == nil {
				t.Fatal("the slot key decrypted twice")
			}
			// Buyer: decode.
			x := p.Recover(c2.C0, pd)
			if p.Scheme() == rlwe.BFV {
				if got := p.DecodeBFV(x, p.Q()); got.Cmp(d.fInt) != 0 {
					t.Fatalf("%s/%s: decoded %s, f = %s", lit.Name, d.name, got, d.fInt)
				}
			} else {
				got := p.DecodeCKKS(x, p.Q())
				diff, _ := new(big.Rat).Sub(got, d.fFixed).Float64()
				if math.Log2(math.Abs(diff)) > rep.LogTau {
					t.Fatalf("%s/%s: error 2^%.2f above tau 2^%.2f", lit.Name, d.name, math.Log2(math.Abs(diff)), rep.LogTau)
				}
				ff, _ := d.fFixed.Float64()
				t.Logf("%s/%s: f = %.6f, |error| = %.3g (tau = 2^%.2f)", lit.Name, d.name, ff, math.Abs(diff), rep.LogTau)
			}
			// A wrong partial decryption or an oversized flood fails pi_dec.
			if p.CheckPDec(c2.C1, slot.KeyWitness.S, new(big.Int).Add(pd, big.NewInt(1)), efl) == nil {
				t.Fatal("CheckPDec accepts a wrong partial decryption")
			}
		}
	}
}
