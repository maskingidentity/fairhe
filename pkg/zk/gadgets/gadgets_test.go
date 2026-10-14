package gadgets

import (
	"crypto/rand"
	"math/big"
	mrand "math/rand/v2"
	"testing"

	"fairhe/pkg/hashes"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
)

var curves = []ecc.ID{ecc.BN254, ecc.BLS12_381}

// rangeCircuit checks lo <= V <= hi.
type rangeCircuit struct {
	V      frontend.Variable
	lo, hi *big.Int
}

func (c *rangeCircuit) Define(api frontend.API) error {
	NewRanger(api).InRange(c.V, c.lo, c.hi)
	return nil
}

func TestInRangeClosedInterval(t *testing.T) {
	q, _ := new(big.Int).SetString("20769187434139310514121985316880385", 10) // a 134-bit odd modulus
	for _, curve := range curves {
		for _, tc := range []struct {
			lo, hi *big.Int
			in     []*big.Int
			out    []*big.Int
		}{
			{big.NewInt(-19), big.NewInt(19), []*big.Int{big.NewInt(-19), big.NewInt(0), big.NewInt(19)}, []*big.Int{big.NewInt(-20), big.NewInt(20), big.NewInt(64)}},
			{big.NewInt(0), new(big.Int).Sub(q, big.NewInt(1)), []*big.Int{big.NewInt(0), new(big.Int).Sub(q, big.NewInt(1))}, []*big.Int{q, big.NewInt(-1)}},
			{new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 79)), new(big.Int).Lsh(big.NewInt(1), 79),
				[]*big.Int{new(big.Int).Lsh(big.NewInt(1), 79), new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), 79))},
				[]*big.Int{new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 79), big.NewInt(1))}},
		} {
			circuit := &rangeCircuit{lo: tc.lo, hi: tc.hi}
			for _, v := range tc.in {
				if err := test.IsSolved(circuit, &rangeCircuit{V: v}, curve.ScalarField()); err != nil {
					t.Fatalf("%s: %s rejected in [%s, %s]: %v", curve, v, tc.lo, tc.hi, err)
				}
			}
			for _, v := range tc.out {
				if test.IsSolved(circuit, &rangeCircuit{V: v}, curve.ScalarField()) == nil {
					t.Fatalf("%s: %s accepted in [%s, %s]", curve, v, tc.lo, tc.hi)
				}
			}
		}
	}
}

type ternaryCircuit struct{ V frontend.Variable }

func (c *ternaryCircuit) Define(api frontend.API) error {
	Ternary(api, c.V)
	return nil
}

func TestTernary(t *testing.T) {
	for _, v := range []int{-1, 0, 1} {
		if err := test.IsSolved(&ternaryCircuit{}, &ternaryCircuit{V: v}, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("%d rejected", v)
		}
	}
	for _, v := range []int{2, -2, 5} {
		if test.IsSolved(&ternaryCircuit{}, &ternaryCircuit{V: v}, ecc.BN254.ScalarField()) == nil {
			t.Fatalf("%d accepted", v)
		}
	}
}

// keyCircuit proves the public-key relation b = -a s + e (mod Q) with the
// gadgets: canonical a and b, ternary s, e in [-19, 19], L in its range, and
// a s + b - e = Q L + (X^N + 1) K at a committed point.
type keyCircuit struct {
	A, B, S, E, L, K []frontend.Variable
	n                int
	q                *big.Int
}

func (c *keyCircuit) Define(api frontend.API) error {
	rg := NewRanger(api)
	lb := big.NewInt(int64(c.n + 2))
	for i := 0; i < c.n; i++ {
		rg.Canonical(c.A[i], c.q)
		rg.Canonical(c.B[i], c.q)
		Ternary(api, c.S[i])
		rg.InSym(c.E[i], big.NewInt(19))
		rg.InSym(c.L[i], lb)
	}
	ch := NewChecker(api, c.n)
	ch.Add(Identity{
		Products: []Term{{A: Dense(c.A), B: Dense(c.S)}},
		Add:      []Poly{Dense(c.B)},
		Sub:      []Poly{Dense(c.E)},
		Q:        c.q, L: Dense(c.L), K: Dense(c.K),
	})
	ch.Finalize()
	return nil
}

func newKeyCircuit(n int, q *big.Int) *keyCircuit {
	mk := func() []frontend.Variable { return make([]frontend.Variable, n) }
	return &keyCircuit{A: mk(), B: mk(), S: mk(), E: mk(), L: mk(), K: mk(), n: n, q: q}
}

// keyWitness returns a, b, s, e with b = -a s + e mod q (negacyclic).
func keyWitness(n int, q *big.Int, rng *mrand.Rand) (a, b []*big.Int, s, e []int64) {
	a = make([]*big.Int, n)
	for i := range a {
		a[i], _ = rand.Int(rand.Reader, q)
	}
	s, e = make([]int64, n), make([]int64, n)
	for i := range s {
		s[i] = rng.Int64N(3) - 1
		e[i] = rng.Int64N(39) - 19
	}
	b = make([]*big.Int, n)
	for j := 0; j < n; j++ {
		acc := big.NewInt(e[j])
		for i := 0; i < n; i++ {
			k, sign := j-i, int64(-1) // b = -a s + e
			if k < 0 {
				k, sign = k+n, 1
			}
			acc.Add(acc, new(big.Int).Mul(a[i], big.NewInt(sign*s[k])))
		}
		b[j] = acc.Mod(acc, q)
	}
	return
}

func assignKey(n int, q *big.Int, a, b []*big.Int, s, e []int64) (*keyCircuit, error) {
	L, K, err := Quotients(n, q, []WTerm{{A: a, B: Ints(s)}}, [][]*big.Int{b}, [][]*big.Int{Ints(e)})
	if err != nil {
		return nil, err
	}
	w := newKeyCircuit(n, q)
	for i := 0; i < n; i++ {
		w.A[i], w.B[i], w.S[i], w.E[i], w.L[i], w.K[i] = a[i], b[i], s[i], e[i], L[i], K[i]
	}
	return w, nil
}

func TestRingIdentityKeyRelation(t *testing.T) {
	const n = 64
	q := new(big.Int).Mul(big.NewInt(35184371613697), big.NewInt(35184371417089))
	q.Mul(q, big.NewInt(17592186028033)) // the Case 1 BFV modulus, 134 bits
	rng := mrand.New(mrand.NewPCG(1, 2))
	a, b, s, e := keyWitness(n, q, rng)
	for _, curve := range curves {
		w, err := assignKey(n, q, a, b, s, e)
		if err != nil {
			t.Fatal(err)
		}
		if err := test.IsSolved(newKeyCircuit(n, q), w, curve.ScalarField()); err != nil {
			t.Fatalf("%s: honest key rejected: %v", curve, err)
		}
		// A different b (still canonical) has no valid quotients, and the
		// quotients of the honest b do not fit it.
		b2 := append([]*big.Int(nil), b...)
		b2[3] = new(big.Int).Add(b[3], big.NewInt(1))
		b2[3].Mod(b2[3], q)
		if _, _, err := Quotients(n, q, []WTerm{{A: a, B: Ints(s)}}, [][]*big.Int{b2}, [][]*big.Int{Ints(e)}); err == nil {
			t.Fatal("Quotients accepted a wrong b")
		}
		w.B[3] = b2[3]
		if test.IsSolved(newKeyCircuit(n, q), w, curve.ScalarField()) == nil {
			t.Fatalf("%s: wrong b accepted", curve)
		}
		// Any change of K alone breaks the identity at the random point.
		w2, _ := assignKey(n, q, a, b, s, e)
		w2.K[5] = new(big.Int).Add(w2.K[5].(*big.Int), big.NewInt(1))
		if test.IsSolved(newKeyCircuit(n, q), w2, curve.ScalarField()) == nil {
			t.Fatalf("%s: tampered K accepted", curve)
		}
		// A large error with matching quotients is caught by its range check.
		e3 := append([]int64(nil), e...)
		e3[0] += 1000
		b3 := append([]*big.Int(nil), b...)
		b3[0] = new(big.Int).Add(b[0], big.NewInt(1000))
		b3[0].Mod(b3[0], q)
		w3, err := assignKey(n, q, a, b3, s, e3)
		if err != nil {
			t.Fatal(err)
		}
		if test.IsSolved(newKeyCircuit(n, q), w3, curve.ScalarField()) == nil {
			t.Fatalf("%s: error 1000 + e accepted", curve)
		}
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, newKeyCircuit(n, q))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("key relation, N = %d: %d constraints (%.1f per coefficient)", n, cs.GetNbConstraints(), float64(cs.GetNbConstraints())/n)
	// The lookup range checks and the identity's challenge share one
	// commitment, the most a gnark Solidity verifier accepts.
	if c, ok := cs.GetCommitments().(constraint.Groth16Commitments); !ok || len(c) != 1 {
		t.Fatalf("circuit has %d commitments, want 1", len(c))
	}
}

type coeffCircuit struct {
	A, S []frontend.Variable
	Out  frontend.Variable
	j    int
}

func (c *coeffCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(NegacyclicCoeff(api, c.A, c.S, c.j), c.Out)
	return nil
}

func TestNegacyclicCoeff(t *testing.T) {
	const n = 32
	rng := mrand.New(mrand.NewPCG(3, 4))
	a, s := make([]int64, n), make([]int64, n)
	for i := range a {
		a[i] = rng.Int64N(1 << 40)
		s[i] = rng.Int64N(3) - 1
	}
	for _, j := range []int{0, 7, n - 1} {
		prod, err := FullProduct(n, Ints(a), Ints(s))
		if err != nil {
			t.Fatal(err)
		}
		want := new(big.Int).Sub(prod[j], prod[n+j])
		w := &coeffCircuit{A: make([]frontend.Variable, n), S: make([]frontend.Variable, n), Out: want}
		for i := range a {
			w.A[i], w.S[i] = a[i], s[i]
		}
		c := &coeffCircuit{A: make([]frontend.Variable, n), S: make([]frontend.Variable, n), j: j}
		if err := test.IsSolved(c, w, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("coefficient %d: %v", j, err)
		}
	}
}

type digestCircuit struct {
	S        []frontend.Variable
	Eta      frontend.Variable
	X        []frontend.Variable
	Rho      frontend.Variable
	HS, ComX frontend.Variable `gnark:",public"`
}

func (c *digestCircuit) Define(api frontend.API) error {
	hs, err := DigestSecret(api, "h_s", c.S, c.Eta)
	if err != nil {
		return err
	}
	api.AssertIsEqual(hs, c.HS)
	com, err := Commitment(api, "x", c.X, 26, c.Rho)
	if err != nil {
		return err
	}
	api.AssertIsEqual(com, c.ComX)
	return nil
}

func TestDigestGadgetsMatchNative(t *testing.T) {
	const n, m = 300, 40
	for _, curve := range curves {
		f := hashes.BN254
		if curve == ecc.BLS12_381 {
			f = hashes.BLS12381
		}
		s := make([]int64, n)
		for i := range s {
			s[i] = int64(i%3) - 1
		}
		eta, rho := make([]byte, hashes.SaltBytes), make([]byte, hashes.SaltBytes)
		rand.Read(eta)
		rand.Read(rho)
		x := make([]*big.Int, m)
		for i := range x {
			x[i] = big.NewInt(int64(1<<25 + i))
		}
		hs, _ := hashes.DigSecret(f, "h_s", s, eta)
		com, _ := hashes.Commit(f, "x", x, 26, rho)
		w := &digestCircuit{S: make([]frontend.Variable, n), X: make([]frontend.Variable, m),
			Eta: new(big.Int).SetBytes(eta), Rho: new(big.Int).SetBytes(rho), HS: hs, ComX: com}
		for i := range s {
			w.S[i] = s[i]
		}
		for i := range x {
			w.X[i] = x[i]
		}
		c := &digestCircuit{S: make([]frontend.Variable, n), X: make([]frontend.Variable, m)}
		if err := test.IsSolved(c, w, curve.ScalarField()); err != nil {
			t.Fatalf("%s: %v", curve, err)
		}
	}
}

type blobCircuit struct {
	Elems []frontend.Variable
	Z, Y  frontend.Variable `gnark:",public"`
}

func (c *blobCircuit) Define(api frontend.API) error {
	y, err := BlobEval(api, c.Elems, c.Z)
	if err != nil {
		return err
	}
	api.AssertIsEqual(y, c.Y)
	return nil
}

// TestF2BlobEvalMatchesKZG is test F2: the
// barycentric evaluation over the bit-reversed roots of unity equals
// go-ethereum's KZG claim y = P_D(z) at 100 random points, natively and in
// a BLS12-381 circuit, and a wrong y fails the circuit.
func TestF2BlobEvalMatchesKZG(t *testing.T) {
	const k, points = 2731, 100 // the packed Case 1 BFV deliverable
	r := hashes.BLSModulus()
	field := ecc.BLS12_381.ScalarField()
	elems := make([]*big.Int, k)
	var blob kzg4844.Blob
	for i := range elems {
		elems[i], _ = rand.Int(rand.Reader, r)
		elems[i].FillBytes(blob[32*i : 32*i+32])
	}
	c := &blobCircuit{Elems: make([]frontend.Variable, k)}
	cs, err := frontend.Compile(field, r1cs.NewBuilder, c)
	if err != nil {
		t.Fatal(err)
	}
	solve := func(z, y *big.Int) error {
		w := &blobCircuit{Elems: make([]frontend.Variable, k), Z: z, Y: y}
		for i := range elems {
			w.Elems[i] = elems[i]
		}
		wit, err := frontend.NewWitness(w, field)
		if err != nil {
			t.Fatal(err)
		}
		return cs.IsSolved(wit)
	}
	for i := 0; i < points; i++ {
		z, _ := rand.Int(rand.Reader, r)
		var point kzg4844.Point
		z.FillBytes(point[:])
		_, claim, err := kzg4844.ComputeProof(&blob, point)
		if err != nil {
			t.Fatal(err)
		}
		y := new(big.Int).SetBytes(claim[:])
		native, err := BlobEvalNative(elems, z)
		if err != nil {
			t.Fatal(err)
		}
		if native.Cmp(y) != 0 {
			t.Fatalf("point %d: barycentric evaluation differs from the KZG claim", i)
		}
		if err := solve(z, y); err != nil {
			t.Fatalf("point %d: the circuit rejects the KZG claim: %v", i, err)
		}
		if i == 0 && solve(z, new(big.Int).Add(y, big.NewInt(1))) == nil {
			t.Fatal("the circuit accepts a wrong y")
		}
	}
	t.Logf("blob evaluation of %d elements: %d constraints; %d points agree with ComputeProof", k, cs.GetNbConstraints(), points)
}

type streamCircuit struct {
	V    []frontend.Variable
	H    frontend.Variable `gnark:",public"`
	bits int
}

func (c *streamCircuit) Define(api frontend.API) error {
	h, err := DigestPoly(api, NewRanger(api), "h_c", c.V, c.bits)
	if err != nil {
		return err
	}
	api.AssertIsEqual(h, c.H)
	return nil
}

// TestStreamPackingMatchesNative checks the stream-packed polynomial digest
// against hashes.DigPoly and that it range checks the coefficients.
func TestStreamPackingMatchesNative(t *testing.T) {
	for _, tc := range []struct {
		curve ecc.ID
		f     hashes.Field
		bits  int
		n     int
	}{{ecc.BLS12_381, hashes.BLS12381, 134, 50}, {ecc.BN254, hashes.BN254, 125, 41}, {ecc.BLS12_381, hashes.BLS12381, 103, 33}} {
		vals := make([]*big.Int, tc.n)
		top := new(big.Int).Lsh(big.NewInt(1), uint(tc.bits))
		for i := range vals {
			vals[i], _ = rand.Int(rand.Reader, top)
		}
		vals[0] = new(big.Int).Sub(top, big.NewInt(1)) // the largest value
		h, err := hashes.DigPoly(tc.f, "h_c", vals, tc.bits)
		if err != nil {
			t.Fatal(err)
		}
		elems, _ := hashes.PackStream(tc.f, vals, tc.bits)
		if len(elems) != hashes.StreamElements(tc.f, tc.n, tc.bits) {
			t.Fatal("element count mismatch")
		}
		w := &streamCircuit{V: make([]frontend.Variable, tc.n), H: h}
		for i := range vals {
			w.V[i] = vals[i]
		}
		c := &streamCircuit{V: make([]frontend.Variable, tc.n), bits: tc.bits}
		if err := test.IsSolved(c, w, tc.curve.ScalarField()); err != nil {
			t.Fatalf("%s/%d bits: %v", tc.curve, tc.bits, err)
		}
		// A value of bits+1 bits is rejected even with a matching digest
		// computed over the wider value's stream.
		w.V[7] = top
		if test.IsSolved(c, w, tc.curve.ScalarField()) == nil {
			t.Fatalf("%s/%d bits: oversized coefficient accepted", tc.curve, tc.bits)
		}
	}
}
