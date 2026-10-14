package decproof

// Tests B6 and B7 (test IDs as in docs/tests.md) for pi_dec:
// it accepts the slot's flooded partial decryption, rejects another secret
// (h_s mismatch), a flood of 2^sigma_fl + 1, another c2,1 (h_c21 mismatch),
// a p that is not the partial decryption and a quotient by Q outside its
// range; its Solidity verifier accepts the proof on the simulated chain only
// for its order ID (B7).

import (
	"crypto/rand"
	"math/big"
	"os"
	"testing"

	"fairhe/pkg/onchain"
	"fairhe/pkg/rlwe"
	"fairhe/pkg/valuation"
	"fairhe/pkg/zk/valclass"
	"fairhe/pkg/zk/zkmeasure"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type instance struct {
	p    *rlwe.Params
	cfg  Config
	slot *rlwe.Slot
	c21  []*big.Int
	pd   *big.Int
	efl  *big.Int
	f    *big.Int // the decoded value (BFV) for the end-to-end check
}

// newInstance prepares a slot for S, lets the buyer evaluate w, and releases
// the partial decryption.
func newInstance(t testing.TB, lit rlwe.ParamsLiteral, cl valclass.Class, S, w []int64) *instance {
	t.Helper()
	p, err := rlwe.NewParams(lit)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ConfigFor(p)
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
	c2, _, err := p.EvalRerand(slot.PK, slot.C1, valuation.EncodeForward(cl.Expand(w), p.N()), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pd, efl, err := slot.PartialDecryptOnce(p, c2.C1, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	in := &instance{p: p, cfg: cfg, slot: slot, c21: p.ToBig(c2.C1), pd: pd, efl: efl}
	if p.Scheme() == rlwe.BFV {
		in.f = p.DecodeBFV(p.Recover(c2.C0, pd), p.Q())
	}
	return in
}

func (in *instance) assign(t testing.TB, orderID int64) *Circuit {
	t.Helper()
	c, _, err := Assign(in.cfg, big.NewInt(orderID), in.c21, in.slot.KeyWitness.S, in.slot.Eta, in.pd, in.efl)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func smallInstance(t testing.TB, lit rlwe.ParamsLiteral, cl valclass.Class) *instance {
	lit.LogN, lit.J = 6, cl.M()-1
	S := make([]int64, cl.M())
	for k := range S {
		S[k] = int64(1)<<(cl.XBits-3) + int64(11*k)
	}
	return newInstance(t, lit, cl, S, []int64{cl.WMax / 4, -cl.WMax / 2})
}

func TestDecProofSmall(t *testing.T) {
	for _, tc := range []struct {
		lit rlwe.ParamsLiteral
		cl  valclass.Class
	}{{rlwe.Case2BFV(), valclass.BFV(2)}, {rlwe.Case2CKKS(), valclass.CKKS(2)}} {
		in := smallInstance(t, tc.lit, tc.cl)
		field := ecc.BN254.ScalarField()
		if err := test.IsSolved(New(in.cfg), in.assign(t, 42), field); err != nil {
			t.Fatalf("%s: honest claim rejected: %v", tc.lit.Name, err)
		}
		// Another secret: the partial decryption under s' presented with
		// the slot's h_s.
		other := smallInstance(t, tc.lit, tc.cl)
		c, _, err := Assign(in.cfg, big.NewInt(42), in.c21, other.slot.KeyWitness.S, other.slot.Eta,
			mustPD(t, in.p, other.slot.SK, in.c21, in.efl), in.efl)
		if err != nil {
			t.Fatal(err)
		}
		c.HS = in.assign(t, 42).HS
		if test.IsSolved(New(in.cfg), c, field) == nil {
			t.Fatalf("%s: another secret accepted", tc.lit.Name)
		}
		// A flood just beyond 2^sigma_fl, with p shifted to match.
		shift := new(big.Int).Lsh(big.NewInt(1), uint(in.cfg.SigmaFl))
		efl := new(big.Int).Add(in.efl, shift)
		efl.Add(efl, big.NewInt(1))
		if efl.CmpAbs(shift) <= 0 {
			efl.Sub(in.efl, shift).Sub(efl, big.NewInt(1))
		}
		pd := new(big.Int).Sub(efl, in.efl)
		pd.Add(pd, in.pd).Mod(pd, in.cfg.Q)
		bad, _, err := Assign(in.cfg, big.NewInt(42), in.c21, in.slot.KeyWitness.S, in.slot.Eta, pd, efl)
		if err != nil {
			t.Fatal(err)
		}
		if test.IsSolved(New(in.cfg), bad, field) == nil {
			t.Fatalf("%s: flood beyond 2^sigma_fl accepted", tc.lit.Name)
		}
		// A different c2,1 than the ordered one (digest mismatch).
		alt := in.assign(t, 42)
		alt.C21[0] = new(big.Int).Add(in.c21[0], big.NewInt(1))
		if test.IsSolved(New(in.cfg), alt, field) == nil {
			t.Fatalf("%s: another c2,1 accepted", tc.lit.Name)
		}
	}
}

func mustPD(t testing.TB, p *rlwe.Params, sk *rlwe.SecretKey, c21 []*big.Int, efl *big.Int) *big.Int {
	t.Helper()
	pd := p.ProductCoeff(p.FromBig(c21), sk.S, p.J())
	pd.Add(pd, efl)
	return pd.Mod(pd, p.Q())
}

// TestB6DecProofBoundaries: p + 1 with the honest witness, and p + 1 with
// the quotient by Q shifted by -Q^-1 in the field, so that the field
// equation holds and only the quotient's range check fails.
func TestB6DecProofBoundaries(t *testing.T) {
	for _, tc := range []struct {
		lit rlwe.ParamsLiteral
		cl  valclass.Class
	}{{rlwe.Case2BFV(), valclass.BFV(2)}, {rlwe.Case2CKKS(), valclass.CKKS(2)}} {
		in := smallInstance(t, tc.lit, tc.cl)
		field := ecc.BN254.ScalarField()
		p1 := new(big.Int).Add(in.pd, big.NewInt(1))
		p1.Mod(p1, in.cfg.Q)
		c := in.assign(t, 42)
		c.P = p1
		if test.IsSolved(New(in.cfg), c, field) == nil {
			t.Fatalf("%s: p other than the partial decryption accepted", tc.lit.Name)
		}
		if p1.Sign() == 0 {
			continue // p = Q - 1: the shifted p would leave [0, Q)
		}
		qinv := new(big.Int).ModInverse(new(big.Int).Mod(in.cfg.Q, field), field)
		c = in.assign(t, 42)
		ell := c.Ell.(*big.Int)
		c.P, c.Ell = p1, new(big.Int).Mod(new(big.Int).Sub(ell, qinv), field)
		// The field equation still holds: (p + 1) + Q (ell - Q^-1) = p + Q ell.
		lhs := new(big.Int).Add(p1, new(big.Int).Mul(in.cfg.Q, c.Ell.(*big.Int)))
		rhs := new(big.Int).Add(in.pd, new(big.Int).Mul(in.cfg.Q, ell))
		if new(big.Int).Mod(lhs, field).Cmp(new(big.Int).Mod(rhs, field)) != 0 {
			t.Fatal("the shifted quotient does not keep the field equation")
		}
		if test.IsSolved(New(in.cfg), c, field) == nil {
			t.Fatalf("%s: a quotient by Q outside its range accepted", tc.lit.Name)
		}
	}
}

// TestDecProofOnChain proves a reduced instance for the Solidity verifier,
// verifies it on the simulated chain, and checks that the same proof is
// refused for another order ID.
func TestDecProofOnChain(t *testing.T) {
	if testing.Short() {
		t.Skip("needs python with py-solc-x")
	}
	in := smallInstance(t, rlwe.Case2BFV(), valclass.BFV(2))
	cs, res, err := zkmeasure.Compile(ecc.BN254, New(in.cfg), "pi_dec", "small")
	if err != nil {
		t.Fatal(err)
	}
	if res.Commitments != 1 {
		t.Fatalf("%d commitments", res.Commitments)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatal(err)
	}
	full, _ := frontend.NewWitness(in.assign(t, 42), ecc.BN254.ScalarField())
	proof, err := groth16.Prove(cs, pk, full, onchain.ProverOption())
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := full.Public()
	if err := groth16.Verify(proof, vk, pub, onchain.VerifierOption()); err != nil {
		t.Fatal(err)
	}
	con, err := onchain.CompileVerifier(vk, "DecVerifierSmall")
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
		t.Fatal("the Solidity verifier rejects the honest proof")
	}
	inputs[0] = big.NewInt(43) // another order ID
	r2, err := onchain.VerifyOnChain(con, pb, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if r2.OK {
		t.Fatal("the Solidity verifier accepts the proof for another order")
	}
	t.Logf("pi_dec on chain: deploy %d gas, verifyProof tx %d gas, proof %d bytes, %d public inputs",
		r.DeployGas, r.VerifyGas, r.ProofBytes, len(inputs))
}

// TestDecProofFullScale measures the full-scale pi_dec (opt-in).
func TestDecProofFullScale(t *testing.T) {
	if os.Getenv("FAIRHE_ZK_FULL") == "" {
		t.Skip("set FAIRHE_ZK_FULL=1")
	}
	only := os.Getenv("FAIRHE_ZK_PARAMS")
	ds := valuation.Generate(71, valuation.NMax)
	for _, tc := range []struct {
		lit rlwe.ParamsLiteral
		cl  valclass.Class
		S   []int64
		w   []int64
	}{
		{rlwe.Case2BFV(), valclass.BFV(valuation.Cols), valuation.Stats(ds), valuation.RandomWeights(72, valuation.WMax)},
		{rlwe.Case2CKKS(), valclass.CKKS(valuation.Cols), valuation.StatsFixed(ds), valuation.RandomWeights(73, valuation.WMaxFixedInt)},
	} {
		if only != "" && only != tc.lit.Name {
			continue
		}
		in := newInstance(t, tc.lit, tc.cl, tc.S, tc.w)
		if in.f != nil && in.f.Cmp(valuation.F(ds, tc.w)) != 0 {
			t.Fatalf("%s: decoded %s, f = %s", tc.lit.Name, in.f, valuation.F(ds, tc.w))
		}
		var res *zkmeasure.Result
		var err error
		if os.Getenv("FAIRHE_ZK_PROVE") != "" {
			res, err = zkmeasure.Measure(ecc.BN254, New(in.cfg), in.assign(t, 42), "pi_dec", tc.lit.Name)
		} else {
			_, res, err = zkmeasure.Compile(ecc.BN254, New(in.cfg), "pi_dec", tc.lit.Name)
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
