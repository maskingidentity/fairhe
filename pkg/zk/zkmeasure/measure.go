// Package zkmeasure is the measurement harness of the proofs: it compiles
// a circuit, runs Groth16 setup, prove and verify on an assignment, and
// records constraints, times, proof size and the process's peak memory
// (Windows: peak working set and peak commit) as JSONL lines. Peaks are
// process-wide high-water marks, so measure one circuit per process.
package zkmeasure

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"fairhe/pkg/clock"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Result is one measured circuit.
type Result struct {
	Time          string    `json:"time"`
	Circuit       string    `json:"circuit"`
	Params        string    `json:"params"`
	Curve         string    `json:"curve"`
	Constraints   int       `json:"constraints"`
	Public        int       `json:"public_inputs"`
	Commitments   int       `json:"commitments"`
	CompileS      float64   `json:"compile_s"`
	SetupS        float64   `json:"setup_s,omitempty"`
	ProveS        float64   `json:"prove_s,omitempty"`  // median of the runs
	VerifyS       float64   `json:"verify_s,omitempty"` // median of the runs
	Reps          int       `json:"reps,omitempty"`
	ProveRuns     []float64 `json:"prove_runs_s,omitempty"`
	VerifyRuns    []float64 `json:"verify_runs_s,omitempty"`
	ProofBytes    int       `json:"proof_bytes,omitempty"`
	PeakRSSGiB    float64   `json:"peak_rss_gib,omitempty"`
	PeakCommitGiB float64   `json:"peak_commit_gib,omitempty"`
	Verified      bool      `json:"verified"`
	GoMaxProcs    int       `json:"gomaxprocs"`
	GitCommit     string    `json:"git_commit"`
	Note          string    `json:"note,omitempty"`
}

// Compile compiles a circuit to R1CS over the curve's scalar field and
// fills the static columns of a result.
func Compile(curve ecc.ID, circuit frontend.Circuit, name, params string) (constraint.ConstraintSystem, *Result, error) {
	start := clock.Now()
	cs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, nil, fmt.Errorf("compile %s: %w", name, err)
	}
	res := &Result{
		Time: time.Now().UTC().Format(time.RFC3339), Circuit: name, Params: params,
		Curve: strings.ToLower(curve.String()), Constraints: cs.GetNbConstraints(),
		Public: cs.GetNbPublicVariables() - 1, CompileS: clock.Since(start).Seconds(),
		GoMaxProcs: runtime.GOMAXPROCS(0), GitCommit: GitCommit(),
	}
	if c, ok := cs.GetCommitments().(constraint.Groth16Commitments); ok {
		res.Commitments = len(c)
	}
	return cs, res, nil
}

// Reps is the number of prove and verify runs of Measure: FAIRHE_ZK_REPS,
// default 1.
func Reps() int {
	if n, err := strconv.Atoi(os.Getenv("FAIRHE_ZK_REPS")); err == nil && n > 0 {
		return n
	}
	return 1
}

// Median returns the median of xs (the mean of the middle two for an even
// count).
func Median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

// Measure compiles and sets up once, then proves the assignment and
// verifies the proof Reps times; the times are the medians.
func Measure(curve ecc.ID, circuit, assignment frontend.Circuit, name, params string) (*Result, error) {
	cs, res, err := Compile(curve, circuit, name, params)
	if err != nil {
		return nil, err
	}
	start := clock.Now()
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return res, fmt.Errorf("setup: %w", err)
	}
	res.SetupS = clock.Since(start).Seconds()
	w, err := frontend.NewWitness(assignment, curve.ScalarField())
	if err != nil {
		return res, err
	}
	pub, err := w.Public()
	if err != nil {
		return res, err
	}
	res.Reps = Reps()
	for i := 0; i < res.Reps; i++ {
		start = clock.Now()
		proof, err := groth16.Prove(cs, pk, w)
		if err != nil {
			return res, fmt.Errorf("prove: %w", err)
		}
		res.ProveRuns = append(res.ProveRuns, clock.Since(start).Seconds())
		var buf bytes.Buffer
		if _, err := proof.WriteTo(&buf); err == nil {
			res.ProofBytes = buf.Len()
		}
		start = clock.Now()
		if err := groth16.Verify(proof, vk, pub); err != nil {
			return res, fmt.Errorf("verify: %w", err)
		}
		res.VerifyRuns = append(res.VerifyRuns, clock.Since(start).Seconds())
	}
	res.ProveS, res.VerifyS = Median(res.ProveRuns), Median(res.VerifyRuns)
	res.Verified = true
	res.FillMemory()
	return res, nil
}

// FillMemory records the process peaks so far.
func (r *Result) FillMemory() {
	if rss, commit, ok := PeakMemory(); ok {
		r.PeakRSSGiB = float64(rss) / (1 << 30)
		r.PeakCommitGiB = float64(commit) / (1 << 30)
	}
}

// Append writes a result as one JSONL line to results/v8/<file> under the
// repository root found from the working directory.
func Append(file string, r *Result) error {
	dir, err := resultsDir()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, file), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(r)
}

// AppendJSON writes any row as one JSONL line to results/v8/<file>.
func AppendJSON(file string, row any) error {
	dir, err := resultsDir()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, file), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(row)
}

func resultsDir() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for d := wd; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			out := filepath.Join(d, "results", "v8")
			return out, os.MkdirAll(out, 0o755)
		}
		if filepath.Dir(d) == d {
			return "", fmt.Errorf("zkmeasure: no go.mod above %s", wd)
		}
	}
}

// GitCommit returns the short hash of HEAD, followed by "-dirty" when the
// tracked files differ from it (empty when git is unavailable).
func GitCommit() string {
	out, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return ""
	}
	c := strings.TrimSpace(string(out))
	if exec.Command("git", "diff", "--quiet", "HEAD").Run() != nil {
		c += "-dirty"
	}
	return c
}
