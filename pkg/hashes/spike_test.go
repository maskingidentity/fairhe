package hashes

// H_dig spike: in-circuit cost per hashed field
// element and native throughput of MiMC, Poseidon2 and GKR-Poseidon2 over the
// two scalar fields the circuits use (BN254 for Case 2, BLS12-381 for
// Case 1). Opt-in, since it compiles several large circuits:
//
//	FAIRHE_SPIKE=1 go test ./pkg/hashes -run TestHDigSpike -v -timeout 60m
//
// Results are appended to results/v8/hdig_spike.jsonl.

import (
	"encoding/json"
	"fmt"
	"hash"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	blsmimc "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	blsposeidon2 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/poseidon2"
	bnfr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bnmimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	bnposeidon2 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stdhash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/hash/poseidon2"
	gkrposeidon2 "github.com/consensys/gnark/std/hash/poseidon2/gkr-poseidon2"
)

type spikeCircuit struct {
	In   []frontend.Variable
	Out  frontend.Variable `gnark:",public"`
	kind string
}

func (c *spikeCircuit) Define(api frontend.API) error {
	var (
		h   stdhash.StateStorer
		err error
	)
	switch c.kind {
	case "mimc":
		h, err = mimc.New(api)
	case "poseidon2":
		h, err = poseidon2.New(api)
	case "gkr-poseidon2":
		h, err = gkrposeidon2.New(api)
	default:
		return fmt.Errorf("unknown hash %q", c.kind)
	}
	if err != nil {
		return err
	}
	h.Write(c.In...)
	api.AssertIsEqual(h.Sum(), c.Out)
	return nil
}

type spikeCurve struct {
	name  string
	id    ecc.ID
	order *big.Int
	// native returns the native hasher of a kind (nil: no native counterpart).
	native func(kind string) hash.Hash
}

var spikeCurves = []spikeCurve{
	{"bn254", ecc.BN254, bnfr.Modulus(), func(kind string) hash.Hash {
		switch kind {
		case "mimc":
			return bnmimc.NewMiMC()
		case "poseidon2", "gkr-poseidon2":
			return bnposeidon2.NewMerkleDamgardHasher()
		}
		return nil
	}},
	{"bls12-381", ecc.BLS12_381, blsfr.Modulus(), func(kind string) hash.Hash {
		switch kind {
		case "mimc":
			return blsmimc.NewMiMC()
		case "poseidon2", "gkr-poseidon2":
			return blsposeidon2.NewMerkleDamgardHasher()
		}
		return nil
	}},
}

type spikeRow struct {
	Curve           string  `json:"curve"`
	Hash            string  `json:"hash"`
	Constraints64   int     `json:"constraints_n64"`
	Constraints1024 int     `json:"constraints_n1024"`
	PerElement      float64 `json:"constraints_per_element"`
	NativeNsPerElem float64 `json:"native_ns_per_element"`
	ProveN          int     `json:"prove_n,omitempty"`
	ProveSec        float64 `json:"prove_s,omitempty"`
	ProveOK         bool    `json:"prove_ok"`
	Err             string  `json:"error,omitempty"`
}

func spikeElems(n int, order *big.Int) []*big.Int {
	out := make([]*big.Int, n)
	for i := range out {
		v := new(big.Int).Lsh(big.NewInt(int64(i+7)), 200)
		out[i] = v.Add(v, big.NewInt(int64(31*i+1))).Mod(v, order)
	}
	return out
}

func nativeDigest(h hash.Hash, elems []*big.Int) []byte {
	h.Reset()
	var buf [32]byte
	for _, e := range elems {
		e.FillBytes(buf[:])
		h.Write(buf[:])
	}
	return h.Sum(nil)
}

func compileCount(curve spikeCurve, kind string, n int) (int, error) {
	c := &spikeCircuit{In: make([]frontend.Variable, n), kind: kind}
	cs, err := frontend.Compile(curve.id.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		return 0, err
	}
	return cs.GetNbConstraints(), nil
}

func TestHDigSpike(t *testing.T) {
	if os.Getenv("FAIRHE_SPIKE") == "" {
		t.Skip("set FAIRHE_SPIKE=1 to run the H_dig spike")
	}
	var rows []spikeRow
	for _, curve := range spikeCurves {
		for _, kind := range []string{"mimc", "poseidon2", "gkr-poseidon2"} {
			row := spikeRow{Curve: curve.name, Hash: kind}
			c64, err := compileCount(curve, kind, 64)
			if err != nil {
				row.Err = err.Error()
				rows = append(rows, row)
				t.Logf("%s/%s: compile failed: %v", curve.name, kind, err)
				continue
			}
			c1024, err := compileCount(curve, kind, 1024)
			if err != nil {
				row.Err = err.Error()
				rows = append(rows, row)
				continue
			}
			row.Constraints64, row.Constraints1024 = c64, c1024
			row.PerElement = float64(c1024-c64) / 960

			// Native throughput over 8192 elements.
			elems := spikeElems(8192, curve.order)
			h := curve.native(kind)
			start := time.Now()
			const reps = 5
			for r := 0; r < reps; r++ {
				nativeDigest(h, elems)
			}
			row.NativeNsPerElem = float64(time.Since(start).Nanoseconds()) / float64(reps*len(elems))

			// Groth16 round trip at n = 256 with the native digest as the
			// public output: checks native/in-circuit agreement and the
			// backend support of the construction on this curve.
			row.ProveN = 256
			in := spikeElems(row.ProveN, curve.order)
			out := new(big.Int).SetBytes(nativeDigest(h, in))
			assign := &spikeCircuit{In: make([]frontend.Variable, row.ProveN), Out: out}
			for i := range in {
				assign.In[i] = in[i]
			}
			if err := spikeProve(curve, kind, row.ProveN, assign, &row); err != nil {
				row.Err = err.Error()
				t.Logf("%s/%s: prove failed: %v", curve.name, kind, err)
			}
			rows = append(rows, row)
			t.Logf("%-9s %-13s n64=%7d n1024=%8d per-elem=%7.1f native=%7.0f ns/elem prove(n=256)=%.2fs ok=%v",
				curve.name, kind, c64, c1024, row.PerElement, row.NativeNsPerElem, row.ProveSec, row.ProveOK)
		}
	}
	writeSpikeRows(t, rows)
}

func spikeProve(curve spikeCurve, kind string, n int, assign *spikeCircuit, row *spikeRow) error {
	c := &spikeCircuit{In: make([]frontend.Variable, n), kind: kind}
	cs, err := frontend.Compile(curve.id.ScalarField(), r1cs.NewBuilder, c)
	if err != nil {
		return err
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return err
	}
	w, err := frontend.NewWitness(assign, curve.id.ScalarField())
	if err != nil {
		return err
	}
	start := time.Now()
	proof, err := groth16.Prove(cs, pk, w)
	if err != nil {
		return err
	}
	row.ProveSec = time.Since(start).Seconds()
	pub, err := w.Public()
	if err != nil {
		return err
	}
	if err := groth16.Verify(proof, vk, pub); err != nil {
		return err
	}
	row.ProveOK = true
	return nil
}

func writeSpikeRows(t *testing.T, rows []spikeRow) {
	dir := filepath.Join("..", "..", "results", "v8")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "hdig_spike.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	stamp := time.Now().UTC().Format(time.RFC3339)
	for _, r := range rows {
		rec := struct {
			Time string `json:"time"`
			spikeRow
		}{stamp, r}
		if err := enc.Encode(rec); err != nil {
			t.Fatal(err)
		}
	}
}
