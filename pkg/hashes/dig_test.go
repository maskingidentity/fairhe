package hashes

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/poseidon2"
	"github.com/consensys/gnark/test"
)

// digCircuit recomputes H_dig in-circuit with gnark's Poseidon2 hasher: the
// tag is a constant of the circuit, the elements are private.
type digCircuit struct {
	Elems []frontend.Variable
	Out   frontend.Variable `gnark:",public"`
	tag   *big.Int
}

func (c *digCircuit) Define(api frontend.API) error {
	h, err := poseidon2.New(api)
	if err != nil {
		return err
	}
	h.Write(c.tag)
	h.Write(c.Elems...)
	api.AssertIsEqual(h.Sum(), c.Out)
	return nil
}

// TestDigMatchesCircuit checks that the native H_dig equals gnark's
// in-circuit Poseidon2 on both fields: the convention the circuits use.
func TestDigMatchesCircuit(t *testing.T) {
	for _, f := range []Field{BN254, BLS12381} {
		vals := make([]*big.Int, 300)
		for i := range vals {
			vals[i] = big.NewInt(int64(1000003*i + 17))
		}
		elems, err := PackBits(f, vals, 68)
		if err != nil {
			t.Fatal(err)
		}
		d, err := Dig(f, "h_D", elems)
		if err != nil {
			t.Fatal(err)
		}
		circuit := &digCircuit{Elems: make([]frontend.Variable, len(elems)), tag: DigTag(f, "h_D", len(elems))}
		assign := &digCircuit{Elems: make([]frontend.Variable, len(elems)), Out: d}
		for i, e := range elems {
			assign.Elems[i] = e
		}
		curve := ecc.BN254
		if f == BLS12381 {
			curve = ecc.BLS12_381
		}
		if err := test.IsSolved(circuit, assign, curve.ScalarField()); err != nil {
			t.Fatalf("%s: native digest does not match the circuit: %v", f, err)
		}
		bad := &digCircuit{Elems: assign.Elems, Out: new(big.Int).Add(d, big.NewInt(1))}
		if test.IsSolved(circuit, bad, curve.ScalarField()) == nil {
			t.Fatalf("%s: circuit accepts a wrong digest", f)
		}
	}
}

func TestPackBits(t *testing.T) {
	if PackPerElement(BN254, 125) != 2 || PackPerElement(BLS12381, 134) != 1 ||
		PackPerElement(BLS12381, 68) != 3 || PackPerElement(BLS12381, 43) != 5 ||
		PackPerElement(BN254, 2) != 126 || PackPerElement(BLS12381, 103) != 2 {
		t.Fatal("unexpected packing densities")
	}
	vals := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}
	e, err := PackBits(BLS12381, vals, 68)
	if err != nil {
		t.Fatal(err)
	}
	want0 := new(big.Int).Lsh(big.NewInt(3), 136)
	want0.Add(want0, new(big.Int).Lsh(big.NewInt(2), 68)).Add(want0, big.NewInt(1))
	if len(e) != 2 || e[0].Cmp(want0) != 0 || e[1].Int64() != 4 {
		t.Fatalf("packing: got %v", e)
	}
	if _, err := PackBits(BN254, []*big.Int{new(big.Int).Lsh(big.NewInt(1), 68)}, 68); err == nil {
		t.Fatal("PackBits accepted a value wider than its bit width")
	}
	if _, err := PackBits(BN254, []*big.Int{big.NewInt(-1)}, 68); err == nil {
		t.Fatal("PackBits accepted a negative value")
	}
}

func TestDigSecretAndCommit(t *testing.T) {
	s := make([]int64, 8192)
	for i := range s {
		s[i] = int64(i%3) - 1
	}
	eta := make([]byte, SaltBytes)
	h1, err := DigSecret(BN254, "h_s", s, eta)
	if err != nil {
		t.Fatal(err)
	}
	eta2 := append([]byte(nil), eta...)
	eta2[0] = 1
	h2, _ := DigSecret(BN254, "h_s", s, eta2)
	s2 := append([]int64(nil), s...)
	s2[4000] = -s2[4000] + 0 // flip one coefficient (0 stays 0, so pick a nonzero one)
	if s2[4000] == s[4000] {
		s2[4001] = -s[4001]
	}
	h3, _ := DigSecret(BN254, "h_s", s2, eta)
	h4, _ := DigSecret(BLS12381, "h_s", s, eta)
	if h1.Cmp(h2) == 0 || h1.Cmp(h3) == 0 || h1.Cmp(h4) == 0 {
		t.Fatal("salted secret digest does not separate salt, secret or field")
	}
	if _, err := DigSecret(BN254, "h_s", []int64{2}, eta); err == nil {
		t.Fatal("DigSecret accepted a non-ternary coefficient")
	}

	x := []*big.Int{big.NewInt(5), big.NewInt(6)}
	c1, _ := Commit(BN254, "x", x, 26, eta)
	c2, _ := Commit(BN254, "x", x, 26, eta2)
	c3, _ := Commit(BN254, "f", x, 26, eta)
	if c1.Cmp(c2) == 0 || c1.Cmp(c3) == 0 {
		t.Fatal("commitment does not separate salts or labels")
	}
	if c1b, _ := Commit(BN254, "x", x, 26, eta); c1b.Cmp(c1) != 0 {
		t.Fatal("commitment is not deterministic")
	}
	if DigTag(BN254, "a", 1).Cmp(DigTag(BN254, "a", 2)) == 0 {
		t.Fatal("tag does not bind the length")
	}
}
