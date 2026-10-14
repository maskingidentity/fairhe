package sealv8

import (
	"crypto/rand"
	"math/big"
	"os"
	"testing"

	"fairhe/pkg/adaptor"
	"fairhe/pkg/hashes"
	"fairhe/pkg/zk/zkmeasure"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

func elems(t *testing.T, f hashes.Field, n int) []*big.Int {
	t.Helper()
	out := make([]*big.Int, n)
	for i := range out {
		out[i], _ = rand.Int(rand.Reader, f.Modulus())
	}
	return out
}

func salt(t *testing.T) []byte {
	t.Helper()
	eta := make([]byte, hashes.SaltBytes)
	rand.Read(eta)
	return eta
}

// TestSealRoundTrip: unsealing with k returns m; another k does not.
func TestSealRoundTrip(t *testing.T) {
	for _, f := range []hashes.Field{hashes.BLS12381, hashes.BN254} {
		k, _, err := adaptor.NewWitness()
		if err != nil {
			t.Fatal(err)
		}
		m := elems(t, f, 5)
		c, err := Seal(f, k, m)
		if err != nil {
			t.Fatal(err)
		}
		back, err := Unseal(f, k, c)
		if err != nil {
			t.Fatal(err)
		}
		for j := range m {
			if back[j].Cmp(m[j]) != 0 || c[j].Cmp(m[j]) == 0 {
				t.Fatalf("field %v: element %d not sealed and opened", f, j)
			}
		}
		k2, _, _ := adaptor.NewWitness()
		if wrong, _ := Unseal(f, k2, c); wrong[0].Cmp(m[0]) == 0 {
			t.Fatalf("field %v: another key opens the seal", f)
		}
	}
}

// TestSealCircuit: pi_seal accepts an honest seal and refuses a seal under
// another key, another Y and another salt behind h_D.
func TestSealCircuit(t *testing.T) {
	for _, f := range []hashes.Field{hashes.BLS12381, hashes.BN254} {
		k, Y, err := adaptor.NewWitness()
		if err != nil {
			t.Fatal(err)
		}
		m, eta := elems(t, f, 3), salt(t)
		a, pub, err := Assign(f, big.NewInt(42), k, Y.X(), Y.Y(), m, eta)
		if err != nil {
			t.Fatal(err)
		}
		mod := CurveOf(f).ScalarField()
		if err := test.IsSolved(New(len(m)), a, mod); err != nil {
			t.Fatalf("field %v: honest seal refused: %v", f, err)
		}
		if len(pub.C) != len(m) {
			t.Fatal("sealed elements missing")
		}
		// A seal under another key, presented with k and Y.
		k2, _, _ := adaptor.NewWitness()
		_, pub2, _ := Assign(f, big.NewInt(42), k2, Y.X(), Y.Y(), m, eta)
		bad := *a
		bad.HC = pub2.HC
		if test.IsSolved(New(len(m)), &bad, mod) == nil {
			t.Fatalf("field %v: a seal under another key accepted", f)
		}
		// Another statement Y.
		_, Y3, _ := adaptor.NewWitness()
		bad = *a
		bad.Y = sw_emulated.AffinePoint[emulated.Secp256k1Fp]{X: emulated.ValueOf[emulated.Secp256k1Fp](Y3.X()), Y: emulated.ValueOf[emulated.Secp256k1Fp](Y3.Y())}
		if test.IsSolved(New(len(m)), &bad, mod) == nil {
			t.Fatalf("field %v: another Y accepted", f)
		}
		// h_D of another salt.
		hd, _ := HD(f, m, salt(t))
		bad = *a
		bad.HD = hd
		if test.IsSolved(New(len(m)), &bad, mod) == nil {
			t.Fatalf("field %v: h_D of another salt accepted", f)
		}
	}
}

// TestSealSize reports the constraints of pi_seal for one element (Case 2)
// and a few (the per-element slope).
func TestSealSize(t *testing.T) {
	for _, f := range []hashes.Field{hashes.BLS12381, hashes.BN254} {
		var prev int
		for _, n := range []int{1, 8} {
			cs, err := frontend.Compile(CurveOf(f).ScalarField(), r1cs.NewBuilder, New(n))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("field %v: %d elements, %d constraints", f, n, cs.GetNbConstraints())
			if cs.GetNbConstraints() <= prev {
				t.Fatal("constraints do not grow with the elements")
			}
			prev = cs.GetNbConstraints()
		}
	}
}

// TestSealFullScale measures pi_seal at the deliverable sizes of the running
// example (opt-in): 2,731 and 1,639 elements over BLS12-381 (Case 1 BFV and
// CKKS) and one element over BN254 (Case 2).
func TestSealFullScale(t *testing.T) {
	if os.Getenv("FAIRHE_ZK_FULL") == "" {
		t.Skip("set FAIRHE_ZK_FULL=1")
	}
	only := os.Getenv("FAIRHE_ZK_PARAMS")
	for _, tc := range []struct {
		params string
		f      hashes.Field
		n      int
	}{{"case1_bfv", hashes.BLS12381, 2731}, {"case1_ckks", hashes.BLS12381, 1639}, {"case2_bfv", hashes.BN254, 1}} {
		if only != "" && only != tc.params {
			continue
		}
		var res *zkmeasure.Result
		var err error
		if os.Getenv("FAIRHE_ZK_PROVE") != "" {
			k, Y, werr := adaptor.NewWitness()
			if werr != nil {
				t.Fatal(werr)
			}
			a, _, aerr := Assign(tc.f, big.NewInt(42), k, Y.X(), Y.Y(), elems(t, tc.f, tc.n), salt(t))
			if aerr != nil {
				t.Fatal(aerr)
			}
			res, err = zkmeasure.Measure(CurveOf(tc.f), New(tc.n), a, "pi_seal", tc.params)
		} else {
			_, res, err = zkmeasure.Compile(CurveOf(tc.f), New(tc.n), "pi_seal", tc.params)
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
		t.Logf("%s/%s: %d constraints, %d public, setup %.1fs, prove %.2fs, verify %.3fs, peak commit %.2f GiB",
			res.Circuit, res.Params, res.Constraints, res.Public, res.SetupS, res.ProveS, res.VerifyS, res.PeakCommitGiB)
	}
}
