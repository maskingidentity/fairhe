package rlwe_test

// Tests A1-A5 (test IDs as in docs/tests.md): 1,000 inputs of
// the running example per parameter set, the first one the worst case
// (statistics at their maximum, weights at +-w_max), through the whole HE
// path. BFV must decode exactly and CKKS within tau (A1-A4), and the noise
// at the released coefficient before the flood must stay below its
// analytic bound, B_tot in Case 1 and B_e + B_err in Case 2 (A5); a larger
// noise would mean that the bound's derivation is wrong. With
// FAIRHE_RECORD=1 the maxima are appended to results/v8/accuracy.jsonl for
// Table 3 of the paper.

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"fairhe/pkg/hashes"
	"fairhe/pkg/rlwe"
	"fairhe/pkg/valuation"
)

// trials is the number of inputs per parameter set: 1,000, or 24 with
// -short.
func trials() int {
	if testing.Short() {
		return 24
	}
	return 1000
}

// valInput is one input of the running example for a parameter set.
type valInput struct {
	enc, pt []int64  // the encrypted message and the plaintext operand (N coefficients)
	ip      *big.Int // <w_hat, S> in integer units
	fInt    *big.Int // BFV: f
	fFixed  *big.Rat // CKKS: f
}

// inputFor returns input i of a set: the worst case for i = 0, otherwise
// random data of 1 to n_max records and random weights. In Case 1 the buyer
// encrypts w_hat and the seller multiplies by S_bar; in Case 2 the roles
// are swapped.
func inputFor(p *rlwe.Params, i int) valInput {
	bfv := p.Scheme() == rlwe.BFV
	wmax := int64(valuation.WMax)
	if !bfv {
		wmax = valuation.WMaxFixedInt
	}
	var ds *valuation.Dataset
	var w valuation.Weights
	if i == 0 {
		ds, w = valuation.WorstCase(), valuation.WorstWeights(wmax)
	} else {
		n := 1 + int(uint64(i)*2654435761%uint64(valuation.NMax))
		ds, w = valuation.Generate(uint64(10_000+i), n), valuation.RandomWeights(uint64(20_000+i), wmax)
	}
	in := valInput{}
	var wh, S []int64
	if bfv {
		wh, S = valuation.ExpandWeights(w), valuation.Stats(ds)
		in.fInt = valuation.F(ds, w)
	} else {
		wh, S = valuation.ExpandWeightsFixed(w), valuation.StatsFixed(ds)
		in.fFixed = valuation.FFixed(S, w)
	}
	in.ip = valuation.InnerProduct(wh, S)
	fwd, rev := valuation.EncodeForward(wh, p.N()), valuation.EncodeReversed(S, p.N())
	if p.Case() == rlwe.Case1 {
		in.enc, in.pt = fwd, rev
	} else {
		in.enc, in.pt = rev, fwd
	}
	return in
}

// centred returns x mod q in (-q/2, q/2].
func centred(x, q *big.Int) *big.Int {
	y := new(big.Int).Mod(x, q)
	if y.Cmp(new(big.Int).Rsh(q, 1)) > 0 {
		y.Sub(y, q)
	}
	return y
}

// preFlood returns the noise of a raw decryption at the released
// coefficient: raw - flood - K_enc K_pt <w_hat, S>, centred mod Q.
func preFlood(p *rlwe.Params, raw, flood, ip *big.Int) *big.Int {
	ideal := new(big.Int).Mul(p.EncScale(), ip)
	ideal.Mul(ideal, big.NewInt(p.PtScale()))
	x := new(big.Int).Sub(raw, ideal)
	if flood != nil {
		x.Sub(x, flood)
	}
	return centred(x, p.Q())
}

// decodeCheck compares the decoded value with f: exact for BFV, the
// absolute error for CKKS.
func decodeCheck(p *rlwe.Params, in valInput, x, modulus *big.Int) (float64, error) {
	if p.Scheme() == rlwe.BFV {
		if got := p.DecodeBFV(x, modulus); got.Cmp(in.fInt) != 0 {
			return 0, fmt.Errorf("decoded %s, f = %s", got, in.fInt)
		}
		return 0, nil
	}
	diff, _ := new(big.Rat).Sub(p.DecodeCKKS(x, modulus), in.fFixed).Float64()
	return math.Abs(diff), nil
}

// case1Trial: the buyer's public-coin key and secret-key encryption of
// w_hat, the seller's product by S_bar and sanitisation (A5 measured here),
// extraction and switch to q_del, and the buyer's decoding.
func case1Trial(p *rlwe.Params, i int) (float64, *big.Int, error) {
	in := inputFor(p, i)
	a, err := p.CoinPoly(hashes.Case1KeyCoin([]byte("buyer"), uint64(i), hashes.LabelPkA))
	if err != nil {
		return 0, nil, err
	}
	sk, pk, _, err := p.KeyGen(a, rand.Reader)
	if err != nil {
		return 0, nil, err
	}
	a1, err := p.FreshUniform(rand.Reader)
	if err != nil {
		return 0, nil, err
	}
	c, _, err := p.EncryptSK(sk, in.enc, a1, rand.Reader)
	if err != nil {
		return 0, nil, err
	}
	prod, err := p.MulPlain(c, in.pt)
	if err != nil {
		return 0, nil, err
	}
	san, sw, err := p.Sanitize(pk, prod, rand.Reader)
	if err != nil {
		return 0, nil, err
	}
	noise := preFlood(p, p.RawDecrypt(sk, san)[p.J()], sw.EFl, in.ip)
	D, _, err := p.ExtractSwitch(san)
	if err != nil {
		return 0, nil, err
	}
	e, err := decodeCheck(p, in, p.DecryptDeliverable(sk, D), p.QDel())
	return e, noise, err
}

// case2Trial: slot i prepared for S_bar, the buyer's evaluation and
// re-randomisation (A5 measured on c2 before the flood), the slot's single
// partial decryption, and the buyer's decoding.
func case2Trial(p *rlwe.Params, i int) (float64, *big.Int, error) {
	in := inputFor(p, i)
	slot, err := p.PrepareSlot([]byte("seller"), []byte("com"), uint64(i+1), in.enc, rand.Reader)
	if err != nil {
		return 0, nil, err
	}
	c2, _, err := p.EvalRerand(slot.PK, slot.C1, in.pt, rand.Reader)
	if err != nil {
		return 0, nil, err
	}
	noise := preFlood(p, p.RawDecrypt(slot.SK, c2)[p.J()], nil, in.ip)
	pd, _, err := slot.PartialDecryptOnce(p, c2.C1, rand.Reader)
	if err != nil {
		return 0, nil, err
	}
	e, err := decodeCheck(p, in, p.Recover(c2.C0, pd), p.Q())
	return e, noise, err
}

// runTrials runs the trials of a set on parallel workers, each with its own
// parameters, and returns the largest CKKS error and pre-flood noise.
func runTrials(t *testing.T, lit rlwe.ParamsLiteral, trial func(*rlwe.Params, int) (float64, *big.Int, error)) (float64, *big.Int) {
	t.Helper()
	type result struct {
		i     int
		err   float64
		noise *big.Int
		fail  error
	}
	workers := min(runtime.GOMAXPROCS(0), 8)
	jobs, out := make(chan int), make(chan result)
	var wg sync.WaitGroup
	for k := 0; k < workers; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, perr := rlwe.NewParams(lit)
			for i := range jobs {
				if perr != nil {
					out <- result{i: i, fail: perr}
					continue
				}
				e, nz, err := trial(p, i)
				out <- result{i, e, nz, err}
			}
		}()
	}
	go func() {
		for i := 0; i < trials(); i++ {
			jobs <- i
		}
		close(jobs)
	}()
	go func() { wg.Wait(); close(out) }()
	maxErr, maxNoise := 0.0, new(big.Int)
	for r := range out {
		if r.fail != nil {
			t.Errorf("%s input %d: %v", lit.Name, r.i, r.fail)
			continue
		}
		maxErr = math.Max(maxErr, r.err)
		if a := new(big.Int).Abs(r.noise); a.Cmp(maxNoise) > 0 {
			maxNoise = a
		}
	}
	return maxErr, maxNoise
}

func TestA1A2A5Case1(t *testing.T) {
	for _, lit := range []rlwe.ParamsLiteral{rlwe.Case1BFV(), rlwe.Case1CKKS()} {
		accuracy(t, lit, case1Trial)
	}
}

func TestA3A4A5Case2(t *testing.T) {
	for _, lit := range []rlwe.ParamsLiteral{rlwe.Case2BFV(), rlwe.Case2CKKS()} {
		accuracy(t, lit, case2Trial)
	}
}

// accuracy runs the trials of a set and checks A1-A4 and A5.
func accuracy(t *testing.T, lit rlwe.ParamsLiteral, trial func(*rlwe.Params, int) (float64, *big.Int, error)) {
	t.Helper()
	p := params(t, lit)
	rep := p.CheckMargins(classBounds(p))
	bound := p.WorstCaseNoise(classBounds(p))
	if p.Case() == rlwe.Case2 { // the buyer's e0' adds B_err to B_e
		bound.Add(bound, big.NewInt(int64(p.BErr())))
	}
	start := time.Now()
	maxErr, maxNoise := runTrials(t, lit, trial)
	secs := time.Since(start).Seconds()
	logNoise, logBound := log2(maxNoise), log2(bound)
	if maxNoise.Cmp(bound) > 0 {
		t.Errorf("A5 %s: pre-flood noise 2^%.2f above the bound 2^%.2f", lit.Name, logNoise, logBound)
	}
	row := map[string]any{"params": lit.Name, "trials": trials(), "log2_max_noise": logNoise, "log2_noise_bound": logBound,
		"seconds": secs, "time": time.Now().UTC().Format(time.RFC3339), "git_commit": gitCommit()}
	if p.Scheme() == rlwe.BFV {
		row["exact"] = !t.Failed()
		t.Logf("%s: %d inputs decoded exactly; pre-flood noise up to 2^%.2f, bound 2^%.2f (%.1f s)",
			lit.Name, trials(), logNoise, logBound, secs)
	} else {
		logErr := math.Log2(maxErr)
		if logErr > rep.LogTau {
			t.Errorf("%s: largest error 2^%.2f above tau 2^%.2f", lit.Name, logErr, rep.LogTau)
		}
		row["max_abs_error"], row["log2_max_abs_error"], row["log2_tau"] = maxErr, logErr, rep.LogTau
		t.Logf("%s: %d inputs, largest error 2^%.2f within tau 2^%.2f; pre-flood noise up to 2^%.2f, bound 2^%.2f (%.1f s)",
			lit.Name, trials(), logErr, rep.LogTau, logNoise, logBound, secs)
	}
	if os.Getenv("FAIRHE_RECORD") != "" && !testing.Short() {
		record(t, "accuracy.jsonl", row)
	}
}

func log2(x *big.Int) float64 {
	if x.Sign() == 0 {
		return math.Inf(-1)
	}
	f, _ := new(big.Float).SetInt(x).Float64()
	return math.Log2(f)
}

// record appends a JSON row to results/v8/<name> at the repository root.
func record(t *testing.T, name string, row map[string]any) {
	t.Helper()
	dir := filepath.Join("..", "..", "results", "v8")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(row); err != nil {
		t.Fatal(err)
	}
}

func gitCommit() string {
	out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
