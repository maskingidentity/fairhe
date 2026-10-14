package valuation

import (
	"math"
	"math/big"
	"testing"
)

func TestSizes(t *testing.T) {
	if M != 528 || J != 527 || Cols != 31 {
		t.Fatalf("M = %d, J = %d, Cols = %d", M, J, Cols)
	}
	if 2*M-1 > 1<<13 {
		t.Fatal("w_hat(X) S_bar(X) wraps around modulo X^N + 1")
	}
	log2 := func(x *big.Int) float64 { f, _ := new(big.Float).SetInt(x).Float64(); return math.Log2(f) }
	if l := log2(SNormL1MaxInt()); l >= 35.1 {
		t.Errorf("||S||_1 bound 2^%.2f, paper says < 2^35.1", l)
	}
	if l := log2(WHatNormL1MaxInt()); l >= 26 {
		t.Errorf("||w_hat||_1 bound 2^%.2f, paper says < 2^26", l)
	}
	if l := log2(FMaxInt()); l >= 52 {
		t.Errorf("f bound 2^%.2f, paper says < 2^52", l)
	}
	if l := log2(SNormL1MaxFixed()); l >= 29.1 {
		t.Errorf("fixed ||S||_1 bound 2^%.2f, paper says < 2^29.1", l)
	}
	if l := log2(WHatNormL1MaxFixed()); l >= 38 {
		t.Errorf("fixed ||w_hat||_1 bound 2^%.2f, paper says < 2^38", l)
	}
	if f, _ := FMaxFixed().Float64(); math.Log2(f) >= 17.92 {
		t.Errorf("fixed f bound 2^%.3f, paper says < 2^17.92", math.Log2(f))
	}
}

// TestIdentity checks f_w = <w_hat, S> against the records (integer version),
// on random data and on the worst case.
func TestIdentity(t *testing.T) {
	cases := []struct {
		name string
		ds   *Dataset
		w    Weights
	}{
		{"random n=100", Generate(1, 100), RandomWeights(2, WMax)},
		{"random n=1024", Generate(3, NMax), RandomWeights(4, WMax)},
		{"worst case", WorstCase(), WorstWeights(WMax)},
		{"worst data, positive weights", WorstCase(), func() Weights {
			w := WorstWeights(WMax)
			for j := range w {
				w[j] = WMax
			}
			return w
		}()},
	}
	for _, c := range cases {
		S := Stats(c.ds)
		wh := ExpandWeights(c.w)
		if len(S) != M || len(wh) != M {
			t.Fatalf("%s: |S| = %d, |w_hat| = %d", c.name, len(S), len(wh))
		}
		got := InnerProduct(wh, S)
		want := F(c.ds, c.w)
		if got.Cmp(want) != 0 {
			t.Fatalf("%s: <w_hat, S> = %s, f_w = %s", c.name, got, want)
		}
		for k, s := range S {
			if s < 0 || s >= 1<<26 {
				t.Fatalf("%s: S[%d] = %d outside [0, 2^26)", c.name, k, s)
			}
		}
		if NormL1(S).Cmp(SNormL1MaxInt()) > 0 {
			t.Fatalf("%s: ||S||_1 above the class bound", c.name)
		}
		if NormL1(wh).Cmp(WHatNormL1MaxInt()) > 0 {
			t.Fatalf("%s: ||w_hat||_1 above the class bound", c.name)
		}
		if want.Sign() < 0 || want.Cmp(FMaxInt()) > 0 {
			t.Fatalf("%s: f = %s outside [0, f_max]", c.name, want)
		}
	}
	// The worst-case weights reach the l1 bound of w_hat exactly.
	if NormL1(ExpandWeights(WorstWeights(WMax))).Cmp(WHatNormL1MaxInt()) != 0 {
		t.Fatal("worst-case weights do not reach (||w||_1 + 2^beta)^2")
	}
}

// TestEncodingProduct checks that coefficient M-1 of w_hat(X) S_bar(X) is
// <w_hat, S> and that the product has degree 2M-2 < N (no wrap-around).
func TestEncodingProduct(t *testing.T) {
	const n = 1 << 13
	ds, w := Generate(5, 300), RandomWeights(6, WMax)
	S, wh := Stats(ds), ExpandWeights(w)
	a, b := EncodeForward(wh, n), EncodeReversed(S, n)
	prod := make([]*big.Int, 2*n-1)
	for i := range prod {
		prod[i] = new(big.Int)
	}
	tmp := new(big.Int)
	for i, x := range a {
		if x == 0 {
			continue
		}
		for j, y := range b {
			if y != 0 {
				prod[i+j].Add(prod[i+j], tmp.Mul(big.NewInt(x), big.NewInt(y)))
			}
		}
	}
	for k := 2*M - 1; k < len(prod); k++ {
		if prod[k].Sign() != 0 {
			t.Fatalf("coefficient %d of the product is nonzero", k)
		}
	}
	if prod[J].Cmp(InnerProduct(wh, S)) != 0 {
		t.Fatal("coefficient M-1 of the product is not <w_hat, S>")
	}
}

// TestFixedPoint checks the CKKS version: S in [0, 2^20], <w_hat, S> 2^-40
// within the rounding of S of the mean squared error, and the class bounds.
func TestFixedPoint(t *testing.T) {
	for _, c := range []struct {
		name string
		ds   *Dataset
		w    Weights
	}{
		{"random", Generate(7, 500), RandomWeights(8, WMaxFixedInt)},
		{"worst case", WorstCase(), WorstWeights(WMaxFixedInt)},
	} {
		S := StatsFixed(c.ds)
		wh := ExpandWeightsFixed(c.w)
		for k, s := range S {
			if s < 0 || s > 1<<FracBits {
				t.Fatalf("%s: S[%d] = %d outside [0, 2^20]", c.name, k, s)
			}
		}
		if NormL1(wh).Cmp(WHatNormL1MaxFixed()) > 0 {
			t.Fatalf("%s: ||w_hat||_1 above the fixed class bound", c.name)
		}
		f := FFixed(S, c.w)
		mse := MSE(c.ds, c.w)
		// Rounding S to 2^-20 moves each term by at most |w_hat_k| 2^-21.
		slack := new(big.Rat).SetFrac(NormL1(wh), new(big.Int).Lsh(big.NewInt(1), 2*FracBits+1))
		diff := new(big.Rat).Sub(f, mse)
		if diff.Abs(diff).Cmp(slack) > 0 {
			ff, _ := f.Float64()
			mm, _ := mse.Float64()
			t.Fatalf("%s: f = %g, MSE = %g, beyond the rounding slack", c.name, ff, mm)
		}
		if new(big.Rat).Abs(f).Cmp(FMaxFixed()) > 0 {
			t.Fatalf("%s: |f| above the fixed class bound", c.name)
		}
	}
}

func TestGenerateDeterministic(t *testing.T) {
	a, b := Generate(9, 64), Generate(9, 64)
	for i := range a.Y {
		if a.Y[i] != b.Y[i] || a.Z[i][3] != b.Z[i][3] {
			t.Fatal("Generate is not deterministic for a fixed seed")
		}
	}
}
