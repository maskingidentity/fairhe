package se

import (
	"crypto/rand"
	"math/big"
	"os"
	"testing"

	"fairhe/pkg/hashes"
	"fairhe/pkg/zk/zkmeasure"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

// encCircuit encrypts k secret elements under a fixed key.
type encCircuit struct {
	M      []frontend.Variable
	Rnd    frontend.Variable
	RX, RY frontend.Variable   `gnark:",public"`
	CT     []frontend.Variable `gnark:",public"`

	pk PublicKey
}

func (c *encCircuit) Define(api frontend.API) error {
	R, ct, err := EncryptCircuit(api, c.pk, c.Rnd, c.M)
	if err != nil {
		return err
	}
	api.AssertIsEqual(R.X, c.RX)
	api.AssertIsEqual(R.Y, c.RY)
	for j := range ct {
		api.AssertIsEqual(ct[j], c.CT[j])
	}
	return nil
}

func newEnc(pk PublicKey, k int) *encCircuit {
	return &encCircuit{M: make([]frontend.Variable, k), CT: make([]frontend.Variable, k), pk: pk}
}

func fieldID(f hashes.Field) ecc.ID {
	if f == hashes.BN254 {
		return ecc.BN254
	}
	return ecc.BLS12_381
}

// TestEncryptAndExtract: the circuit accepts the native encryption, the
// extractor recovers the elements with sk, and a ciphertext of other
// elements is refused.
func TestEncryptAndExtract(t *testing.T) {
	for _, f := range []hashes.Field{hashes.BLS12381, hashes.BN254} {
		sk, pk, err := KeyGen(f, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		m := []*big.Int{big.NewInt(0), big.NewInt(7), new(big.Int).Lsh(big.NewInt(1), 250)}
		r, rx, ry, ct, err := Encrypt(pk, m, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Extract(f, sk, rx, ry, ct)
		if err != nil {
			t.Fatal(err)
		}
		for j := range m {
			if got[j].Cmp(m[j]) != 0 {
				t.Fatalf("field %v: element %d extracted as %s", f, j, got[j])
			}
		}
		w := newEnc(pk, len(m))
		w.Rnd, w.RX, w.RY = r, rx, ry
		for j := range m {
			w.M[j], w.CT[j] = m[j], ct[j]
		}
		mod := fieldID(f).ScalarField()
		if err := test.IsSolved(newEnc(pk, len(m)), w, mod); err != nil {
			t.Fatalf("field %v: the circuit refuses the native encryption: %v", f, err)
		}
		w.M[1] = big.NewInt(8) // the public ciphertext no longer encrypts the witness
		if test.IsSolved(newEnc(pk, len(m)), w, mod) == nil {
			t.Fatalf("field %v: a ciphertext of other elements accepted", f)
		}
	}
}

// TestCostModel compiles the encryption of k elements and reports the
// constraints: a fixed part (two scalar multiplications) plus one keystream
// hash per element. With FAIRHE_RECORD=1 the rows go to results/v8/se.jsonl.
func TestCostModel(t *testing.T) {
	for _, f := range []hashes.Field{hashes.BLS12381, hashes.BN254} {
		_, pk, err := KeyGen(f, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		var prev int
		for _, k := range []int{1, 2, 8, 32, 64} {
			cs, err := frontend.Compile(fieldID(f).ScalarField(), r1cs.NewBuilder, newEnc(pk, k))
			if err != nil {
				t.Fatal(err)
			}
			n := cs.GetNbConstraints()
			t.Logf("field %v: %3d elements, %6d constraints", f, k, n)
			if n <= prev {
				t.Fatalf("field %v: constraints do not grow with the elements", f)
			}
			prev = n
			if os.Getenv("FAIRHE_RECORD") != "" {
				row := map[string]any{"field": fieldID(f).String(), "elements": k, "constraints": n, "git_commit": zkmeasure.GitCommit()}
				if err := zkmeasure.AppendJSON("se.jsonl", row); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
