package evalc1

// Tests B4 and B7 (test IDs as in docs/tests.md) for the
// Case 1 evaluation proof: it accepts the honest claim and rejects wrong
// witnesses, each breaking one check (TestB4EvalC1Boundaries), and a proof
// binds its order ID (B7). Full scale is opt-in:
//
//	FAIRHE_ZK_FULL=1 go test ./pkg/zk/evalc1 -run TestEvalC1FullScale -v -timeout 6h
//	  (add FAIRHE_ZK_PROVE=1 for setup, prove and verify)

import (
	"crypto/rand"
	"math/big"
	mrand "math/rand/v2"
	"os"
	"testing"

	"fairhe/pkg/hashes"
	"fairhe/pkg/onchain"
	"fairhe/pkg/rlwe"
	"fairhe/pkg/valuation"
	"fairhe/pkg/zk/gadgets"
	"fairhe/pkg/zk/zkmeasure"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// claim runs the rlwe Case 1 path for messages w_hat (forward) and S
// (reversed into S_bar) and returns the circuit inputs and the sanitised
// ciphertext.
func claim(t testing.TB, p *rlwe.Params, wh, S []int64) (*Inputs, *rlwe.Ciphertext) {
	t.Helper()
	m := len(S)
	a, err := p.CoinPoly(hashes.Case1KeyCoin([]byte("buyer"), 0, hashes.LabelPkA))
	if err != nil {
		t.Fatal(err)
	}
	sk, pk, _, err := p.KeyGen(a, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a1, _ := p.FreshUniform(rand.Reader)
	c, _, err := p.EncryptSK(sk, wh, a1, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sbar := make([]int64, p.N())
	for k, x := range S {
		sbar[m-1-k] = x
	}
	prod, err := p.MulPlain(c, sbar)
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
	if err := p.CheckCase1Eval(c, pk, sbar, sw, D, xw); err != nil {
		t.Fatal(err)
	}
	rho := make([]byte, hashes.SaltBytes)
	rand.Read(rho)
	z, _ := rand.Int(rand.Reader, hashes.BLSModulus())
	return &Inputs{Params: p, OrderID: big.NewInt(42), PK: pk, C: c, X: S, Rho: rho, San: sw, Del: D, Sw: xw, Z: z}, san
}

// small returns a reduced instance: N = 64, m = 8, released coefficient 7,
// with the primes, q_del and flood of a flagship set, and data of xBits bits
// (at most xMax if it is not nil).
func small(t testing.TB, lit rlwe.ParamsLiteral, xBits int, xMax *big.Int) (Config, *Inputs, *rlwe.Ciphertext) {
	t.Helper()
	const m = 8
	lit.LogN, lit.J = 6, m-1
	p, err := rlwe.NewParams(lit)
	if err != nil {
		t.Fatal(err)
	}
	rng := mrand.New(mrand.NewPCG(5, 6))
	top := int64(1)<<xBits - 1
	if xMax != nil {
		top = xMax.Int64()
	}
	S, wh := make([]int64, m), make([]int64, m)
	for k := range S {
		S[k] = rng.Int64N(top + 1)
		wh[k] = rng.Int64N(1<<20) - 1<<19
	}
	sNorm := new(big.Int).Lsh(big.NewInt(m), uint(xBits))
	cfg, err := ConfigFor(p, m, xBits, xMax, sNorm)
	if err != nil {
		t.Fatal(err)
	}
	in, san := claim(t, p, wh, S)
	return cfg, in, san
}

func TestEvalC1Small(t *testing.T) {
	for _, tc := range []struct {
		lit   rlwe.ParamsLiteral
		xBits int
		xMax  *big.Int
	}{{rlwe.Case1BFV(), 26, nil}, {rlwe.Case1CKKS(), 21, big.NewInt(1 << valuation.FracBits)}} {
		cfg, in, _ := small(t, tc.lit, tc.xBits, tc.xMax)
		w, _, err := Assign(cfg, in)
		if err != nil {
			t.Fatal(err)
		}
		field := ecc.BLS12_381.ScalarField()
		if err := test.IsSolved(New(cfg), w, field); err != nil {
			t.Fatalf("%s: honest claim rejected: %v", tc.lit.Name, err)
		}
		mutate := map[string]func(c *Circuit){
			"deliverable coefficient": func(c *Circuit) { c.D[3] = new(big.Int).Add(c.D[3].(*big.Int), big.NewInt(1)) },
			"oversized flood": func(c *Circuit) {
				c.EFl = new(big.Int).Lsh(big.NewInt(1), uint(cfg.SigmaFl+1))
			},
			"other data":       func(c *Circuit) { c.X[0] = new(big.Int).Add(c.X[0].(*big.Int), big.NewInt(1)) },
			"evaluation point": func(c *Circuit) { c.Z = new(big.Int).Add(in.Z, big.NewInt(1)) },
			"rounding remainder": func(c *Circuit) {
				c.R[5] = new(big.Int).Add(c.R[5].(*big.Int), big.NewInt(1))
			},
			"re-randomiser": func(c *Circuit) { c.V[2] = 2 },
		}
		for name, f := range mutate {
			bad, _, _ := Assign(cfg, in)
			f(bad)
			if test.IsSolved(New(cfg), bad, field) == nil {
				t.Fatalf("%s: %s accepted", tc.lit.Name, name)
			}
		}
	}
}

// TestB4EvalC1Boundaries: each wrong witness breaks one check only. The
// claim is recomputed for a data entry of 2^20 + 1 in the fixed-point class
// (2^20, and 2^26 - 1 in the integer class, pass); the sanitised ciphertext
// and D are recomputed for a flood of 2^sigma_fl + 1, a re-randomiser
// coefficient 2 and errors of +-20 (the boundary values and ternary
// coefficients pass); D_j + 1 with r_j + Q leaves |r_j| <= Q/2;
// D_j + Q^-1 in the field with r_j + 1 (h_D and y_z recomputed) leaves
// D_j in [0, q_del); the released coefficient or a coefficient of the
// second component + 1 with its quotient by Q shifted by -Q^-1 leaves the
// quotient's range; and Com(x) of other data, other h_c and h_pk, an h_D
// that D does not have and a wrong y_z fail their public checks.
func TestB4EvalC1Boundaries(t *testing.T) {
	for _, tc := range []struct {
		lit   rlwe.ParamsLiteral
		xBits int
		xMax  *big.Int
	}{{rlwe.Case1BFV(), 26, nil}, {rlwe.Case1CKKS(), 21, big.NewInt(1 << valuation.FracBits)}} {
		cfg, in, san := small(t, tc.lit, tc.xBits, tc.xMax)
		p, field, name := in.Params, ecc.BLS12_381.ScalarField(), tc.lit.Name
		J, Q := p.J(), cfg.Q
		qinv := new(big.Int).ModInverse(new(big.Int).Mod(Q, field), field)
		solve := func(in2 *Inputs) error {
			w, _, err := Assign(cfg, in2)
			if err != nil {
				t.Fatal(err)
			}
			return test.IsSolved(New(cfg), w, field)
		}
		expect := func(what string, err error, accept bool) {
			t.Helper()
			if accept != (err == nil) {
				t.Fatalf("%s: %s: accepted = %v", name, what, err == nil)
			}
		}
		// resanitised returns the inputs for another sanitised ciphertext
		// and its witness, with D and the switch witness recomputed.
		resanitised := func(c0, c1 ring.Poly, sw *rlwe.SanitizeWitness) *Inputs {
			D, xw, err := p.ExtractSwitch(&rlwe.Ciphertext{C0: c0, C1: c1})
			if err != nil {
				t.Fatal(err)
			}
			in2 := *in
			in2.San, in2.Del, in2.Sw = sw, D, xw
			return &in2
		}
		cp := func() *rlwe.SanitizeWitness {
			z := in.San.ZeroEncWitness
			return &rlwe.SanitizeWitness{ZeroEncWitness: rlwe.ZeroEncWitness{V: append([]int64(nil), z.V...),
				E0: append([]int64(nil), z.E0...), E1: append([]int64(nil), z.E1...)}, EFl: new(big.Int).Set(in.San.EFl)}
		}
		mono := func(i int, v int64) []int64 {
			m := make([]int64, p.N())
			m[i] = v
			return m
		}
		expect("honest claim", solve(in), true)

		// The data range: an entry at the largest value of the class is
		// accepted and, where that value lies below 2^XBits (the fixed-point
		// class), the next one is refused; the claim is recomputed for the
		// new data.
		xTop := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(cfg.XBits)), big.NewInt(1))
		if cfg.XMax != nil {
			xTop = cfg.XMax
		}
		for _, d := range []int64{0, 1} {
			if d == 1 && cfg.XMax == nil {
				break // 2^XBits does not fit the limbs of Com(x)
			}
			S := append([]int64(nil), in.X...)
			S[0] = xTop.Int64() + d
			ones := make([]int64, len(S))
			for k := range ones {
				ones[k] = 1
			}
			in2, _ := claim(t, p, ones, S)
			expect("data entry "+big.NewInt(S[0]).String(), solve(in2), d == 0)
		}

		// The flood at +-2^sigma (accepted) and +-(2^sigma + 1).
		top := new(big.Int).Lsh(big.NewInt(1), uint(cfg.SigmaFl))
		over := new(big.Int).Add(top, big.NewInt(1))
		for _, v := range []*big.Int{top, new(big.Int).Neg(top), over, new(big.Int).Neg(over)} {
			sw := cp()
			d := new(big.Int).Sub(v, sw.EFl)
			sw.EFl = v
			c0 := p.Copy(san.C0)
			p.AddToCoeff(c0, J, d)
			expect("flood "+v.String(), solve(resanitised(c0, p.Copy(san.C1), sw)), v.CmpAbs(top) <= 0)
		}
		// The re-randomiser: v_i = 1 -> 0 (accepted) and 1 -> 2.
		i := 0
		for in.San.V[i] != 1 {
			i++
		}
		for _, step := range []int64{-1, 1} {
			sw := cp()
			sw.V[i] += step
			c0 := p.Add(san.C0, p.MulSmall(in.PK.B, mono(i, step)))
			c1 := p.Add(san.C1, p.MulSmall(in.PK.A, mono(i, step)))
			expect("re-randomiser coefficient "+big.NewInt(sw.V[i]).String(), solve(resanitised(c0, c1, sw)), sw.V[i] == 0)
		}
		// The errors e1'_3 and e0'_J at +-19 (accepted) and +-20.
		for _, v := range []int64{19, -19, 20, -20} {
			sw := cp()
			d := v - sw.E1[3]
			sw.E1[3] = v
			expect("e1' coefficient "+big.NewInt(v).String(),
				solve(resanitised(p.Copy(san.C0), p.Add(san.C1, p.FromSmall(mono(3, d))), sw)), v == 19 || v == -19)
			sw = cp()
			d = v - sw.E0[J]
			sw.E0[J] = v
			c0 := p.Copy(san.C0)
			p.AddToCoeff(c0, J, big.NewInt(d))
			expect("e0' coefficient "+big.NewInt(v).String(), solve(resanitised(c0, p.Copy(san.C1), sw)), v == 19 || v == -19)
		}

		// The rounding: D_j + 1 with r_j + Q, so |r_j| > Q/2.
		j := 0
		for in.Del.D1[j].Cmp(new(big.Int).Sub(cfg.QDel, big.NewInt(1))) >= 0 {
			j++
		}
		in2 := *in
		in2.Del = &rlwe.Deliverable{D0: in.Del.D0, D1: append([]*big.Int(nil), in.Del.D1...)}
		in2.Sw = &rlwe.SwitchWitness{C0J: in.Sw.C0J, C1: in.Sw.C1, R0: in.Sw.R0, R1: append([]*big.Int(nil), in.Sw.R1...)}
		in2.Del.D1[j] = new(big.Int).Add(in.Del.D1[j], big.NewInt(1))
		in2.Sw.R1[j] = new(big.Int).Add(in.Sw.R1[j], Q)
		expect("rounding remainder beyond Q/2", solve(&in2), false)

		// D_j + Q^-1 in the field with r_j + 1: the switch equation holds in
		// the field; h_D and y_z are those of the shifted blob element.
		w, pub, err := Assign(cfg, in)
		if err != nil {
			t.Fatal(err)
		}
		k := 6
		Dk := new(big.Int).Add(w.D[k].(*big.Int), qinv)
		w.D[k] = Dk.Mod(Dk, field)
		w.R[k] = new(big.Int).Add(w.R[k].(*big.Int), big.NewInt(1))
		elems := append([]*big.Int(nil), pub.Elems...)
		e := new(big.Int).Lsh(qinv, uint(cfg.DBits*(k%cfg.DPer)))
		e.Add(e, elems[k/cfg.DPer])
		elems[k/cfg.DPer] = e.Mod(e, field)
		hd, err := hashes.Dig(hashes.BLS12381, LabelHD, elems)
		if err != nil {
			t.Fatal(err)
		}
		yz, err := gadgets.BlobEvalNative(elems, in.Z)
		if err != nil {
			t.Fatal(err)
		}
		w.HD, w.YZ = hd, yz
		lhs := new(big.Int).Mul(Q, new(big.Int).Add(w.D[k].(*big.Int), new(big.Int).Mul(w.W[k].(*big.Int), cfg.QDel)))
		rhs := new(big.Int).Add(new(big.Int).Mul(cfg.QDel, in.Sw.C1[k-1]), w.R[k].(*big.Int))
		if new(big.Int).Mod(lhs.Sub(lhs, rhs), field).Sign() != 0 {
			t.Fatal("the shifted D_j does not keep the switch equation in the field")
		}
		expect("D_j outside [0, q_del)", test.IsSolved(New(cfg), w, field), false)

		// The quotients by Q: the released coefficient + 1 with ell0 - Q^-1
		// and r_0 - q_del, and c_san,1[2] + 1 with L_2 - Q^-1 and r_3 - q_del.
		shift := func(c, q, r *frontend.Variable) {
			*c = new(big.Int).Add((*c).(*big.Int), big.NewInt(1))
			*q = new(big.Int).Mod(new(big.Int).Sub(toBig(*q), qinv), field)
			*r = new(big.Int).Sub((*r).(*big.Int), cfg.QDel)
		}
		w, _, _ = Assign(cfg, in)
		shift(&w.CS0J, &w.Ell0, &w.R[0])
		expect("released coefficient's quotient outside its range", test.IsSolved(New(cfg), w, field), false)
		w, _, _ = Assign(cfg, in)
		shift(&w.CS1[2], &w.L[2], &w.R[3])
		expect("product quotient outside its range", test.IsSolved(New(cfg), w, field), false)

		// Public values that the witness does not match.
		other := append([]int64(nil), in.X...)
		other[0]++
		otherCom, err := hashes.Commit(hashes.BLS12381, LabelX, gadgets.Ints(other), cfg.XBits, in.Rho)
		if err != nil {
			t.Fatal(err)
		}
		inc := func(v frontend.Variable) *big.Int { return new(big.Int).Add(v.(*big.Int), big.NewInt(1)) }
		for what, f := range map[string]func(c *Circuit){
			"Com(x) of other data":        func(c *Circuit) { c.ComX = otherCom },
			"another h_c":                 func(c *Circuit) { c.HC = inc(c.HC) },
			"another h_pk":                func(c *Circuit) { c.HPk = inc(c.HPk) },
			"an h_D that D does not have": func(c *Circuit) { c.HD = inc(c.HD) },
			"a wrong y_z":                 func(c *Circuit) { c.YZ = inc(c.YZ) },
		} {
			w, _, _ := Assign(cfg, in)
			f(w)
			expect(what, test.IsSolved(New(cfg), w, field), false)
		}
	}
}

// toBig returns an assigned value as a big integer.
func toBig(v frontend.Variable) *big.Int {
	switch x := v.(type) {
	case *big.Int:
		return x
	case int64:
		return big.NewInt(x)
	case int:
		return big.NewInt(int64(x))
	}
	panic("evalc1: unexpected assignment type")
}

// TestEvalC1Groth16Small proves a reduced instance and checks that the proof
// verifies only for its order ID, with one commitment.
func TestEvalC1Groth16Small(t *testing.T) {
	cfg, in, _ := small(t, rlwe.Case1BFV(), 26, nil)
	w, _, err := Assign(cfg, in)
	if err != nil {
		t.Fatal(err)
	}
	cs, res, err := zkmeasure.Compile(ecc.BLS12_381, New(cfg), "pi_eval_c1", "small")
	if err != nil {
		t.Fatal(err)
	}
	if res.Commitments != 1 {
		t.Fatalf("%d commitments, want 1", res.Commitments)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatal(err)
	}
	full, _ := frontend.NewWitness(w, ecc.BLS12_381.ScalarField())
	proof, err := groth16.Prove(cs, pk, full)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := full.Public()
	if err := groth16.Verify(proof, vk, pub); err != nil {
		t.Fatal(err)
	}
	other := *w
	other.OrderID = big.NewInt(43)
	otherW, _ := frontend.NewWitness(&other, ecc.BLS12_381.ScalarField(), frontend.PublicOnly())
	if groth16.Verify(proof, vk, otherW) == nil {
		t.Fatal("the proof verifies for another order ID")
	}
	t.Logf("small instance: %d constraints, %d public inputs", res.Constraints, res.Public)
}

// TestEvalC1FullScale compiles (and optionally proves) the full-scale
// circuits of Case 1 BFV and CKKS on the running example.
func TestEvalC1FullScale(t *testing.T) {
	if os.Getenv("FAIRHE_ZK_FULL") == "" {
		t.Skip("set FAIRHE_ZK_FULL=1")
	}
	only := os.Getenv("FAIRHE_ZK_PARAMS") // "case1_bfv" or "case1_ckks" (default both)
	for _, lit := range []rlwe.ParamsLiteral{rlwe.Case1BFV(), rlwe.Case1CKKS()} {
		if only != "" && only != lit.Name {
			continue
		}
		p := rlwe.MustParams(lit)
		var (
			cfg Config
			err error
			wh  []int64
			S   []int64
		)
		ds := valuation.Generate(31, valuation.NMax)
		if lit.Scheme == rlwe.BFV {
			cfg, err = ConfigFor(p, valuation.M, 26, nil, valuation.SNormL1MaxInt())
			wh = valuation.ExpandWeights(valuation.RandomWeights(32, valuation.WMax))
			S = valuation.Stats(ds)
		} else {
			cfg, err = ConfigFor(p, valuation.M, valuation.FracBits+1, big.NewInt(1<<valuation.FracBits), valuation.SNormL1MaxFixed())
			wh = valuation.ExpandWeightsFixed(valuation.RandomWeights(32, valuation.WMaxFixedInt))
			S = valuation.StatsFixed(ds)
		}
		if err != nil {
			t.Fatal(err)
		}
		if os.Getenv("FAIRHE_ZK_PROVE") == "" {
			_, res, err := zkmeasure.Compile(ecc.BLS12_381, New(cfg), "pi_eval_c1", lit.Name)
			if err != nil {
				t.Fatal(err)
			}
			res.Note = "compile only"
			record(t, res)
			continue
		}
		in, _ := claim(t, p, valuation.EncodeForward(wh, p.N()), S)
		w, _, err := Assign(cfg, in)
		if err != nil {
			t.Fatal(err)
		}
		res, err := zkmeasure.Measure(ecc.BLS12_381, New(cfg), w, "pi_eval_c1", lit.Name)
		if err != nil {
			t.Fatal(err)
		}
		record(t, res)
	}
}

func record(t *testing.T, res *zkmeasure.Result) {
	t.Helper()
	res.FillMemory()
	if err := zkmeasure.Append("zk.jsonl", res); err != nil {
		t.Fatal(err)
	}
	t.Logf("%s/%s: %d constraints, %d public, %d commitment(s), compile %.1fs, setup %.1fs, prove %.1fs, verify %.3fs, proof %d B, peak RSS %.2f GiB, peak commit %.2f GiB",
		res.Circuit, res.Params, res.Constraints, res.Public, res.Commitments, res.CompileS, res.SetupS, res.ProveS, res.VerifyS, res.ProofBytes, res.PeakRSSGiB, res.PeakCommitGiB)
}

// TestEvalC1OnChainSmall proves a reduced instance for the BLS12-381
// Solidity verifier (EIP-2537 precompiles), verifies it on the simulated
// chain, and checks that the proof is refused for another order ID.
func TestEvalC1OnChainSmall(t *testing.T) {
	if testing.Short() {
		t.Skip("needs python with py-solc-x")
	}
	cfg, in, _ := small(t, rlwe.Case1BFV(), 26, nil)
	w, _, err := Assign(cfg, in)
	if err != nil {
		t.Fatal(err)
	}
	cs, _, err := zkmeasure.Compile(ecc.BLS12_381, New(cfg), "pi_eval_c1", "small")
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatal(err)
	}
	full, _ := frontend.NewWitness(w, ecc.BLS12_381.ScalarField())
	proof, err := groth16.Prove(cs, pk, full, onchain.ProverOption())
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := full.Public()
	if err := groth16.Verify(proof, vk, pub, onchain.VerifierOption()); err != nil {
		t.Fatal(err)
	}
	con, err := onchain.CompileVerifier(vk, "EvalC1VerifierSmall")
	if err != nil {
		t.Fatal(err)
	}
	pb, _ := onchain.ProofBytes(proof)
	inputs, err := onchain.PublicInputs(pub)
	if err != nil {
		t.Fatal(err)
	}
	r, err := onchain.VerifyOnChain(con, pb, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if !r.OK {
		t.Fatal("the BLS12-381 Solidity verifier rejects the honest proof")
	}
	inputs[0] = big.NewInt(43)
	r2, err := onchain.VerifyOnChain(con, pb, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if r2.OK {
		t.Fatal("the verifier accepts the proof for another order")
	}
	t.Logf("pi_eval C1 on chain: deploy %d gas, verifyProof tx %d gas, proof %d bytes, %d public inputs",
		r.DeployGas, r.VerifyGas, r.ProofBytes, len(inputs))
}
