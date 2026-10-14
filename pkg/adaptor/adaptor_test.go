package adaptor

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func digest(t *testing.T, s string) [32]byte {
	t.Helper()
	return sha256.Sum256([]byte(s))
}

func mustKeyGen(t *testing.T) (*PrivateKey, *Point) {
	t.Helper()
	d, P, err := KeyGen()
	if err != nil {
		t.Fatal(err)
	}
	return d, P
}

// TestSignVerifyRoundtrip: a plain signature verifies, and Verify rejects any
// modification of m, R, or s (micro-suite plus negative checks).
func TestSignVerifyRoundtrip(t *testing.T) {
	d, P := mustKeyGen(t)
	m := digest(t, "settlement digest")
	sig, err := Sign(d, m)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(P, m, sig) {
		t.Fatal("valid signature rejected")
	}
	// modified message
	m2 := m
	m2[0] ^= 0x01
	if Verify(P, m2, sig) {
		t.Fatal("signature accepted under modified message")
	}
	// modified s
	sBad := new(big.Int).Add(sig.S, big.NewInt(1))
	sBad.Mod(sBad, n)
	if Verify(P, m, Sig{R: sig.R, S: sBad}) {
		t.Fatal("signature accepted with modified s")
	}
	// out-of-range s
	if Verify(P, m, Sig{R: sig.R, S: new(big.Int).Add(sig.S, n)}) {
		t.Fatal("signature accepted with non-canonical s >= n")
	}
	// modified R (some other point)
	_, R2 := mustKeyGen(t)
	if Verify(P, m, Sig{R: R2, S: sig.S}) {
		t.Fatal("signature accepted with modified R")
	}
	// wrong public key
	_, P2 := mustKeyGen(t)
	if Verify(P2, m, sig) {
		t.Fatal("signature accepted under wrong public key")
	}
}

// TestPreSigIsNotASignature: property (i) — a pre-signature does
// not pass plain verification (the K offset is missing from shat*G).
func TestPreSigIsNotASignature(t *testing.T) {
	d, P := mustKeyGen(t)
	_, K, err := NewWitness()
	if err != nil {
		t.Fatal(err)
	}
	m := digest(t, "presig is not a sig")
	ps, err := PreSign(d, m, K)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPreSig(P, m, K, ps) {
		t.Fatal("valid pre-signature rejected by VerifyPreSig")
	}
	if Verify(P, m, Sig{R: ps.R, S: ps.Shat}) {
		t.Fatal("pre-signature accepted as a plain signature")
	}
}

// TestAdaptCorrectWitness: property (ii) — adapting with the correct witness
// yields a signature that Verify accepts.
func TestAdaptCorrectWitness(t *testing.T) {
	d, P := mustKeyGen(t)
	k, K, err := NewWitness()
	if err != nil {
		t.Fatal(err)
	}
	m := digest(t, "adapt with correct witness")
	ps, err := PreSign(d, m, K)
	if err != nil {
		t.Fatal(err)
	}
	sig := Adapt(ps, k)
	if !Verify(P, m, sig) {
		t.Fatal("adapted signature rejected")
	}
	if sig.R != ps.R {
		t.Fatal("Adapt must keep R unchanged")
	}
}

// TestExtractRecoversWitness: property (iii) — Extract(ps, Adapt(ps, k))
// returns exactly k.
func TestExtractRecoversWitness(t *testing.T) {
	d, _ := mustKeyGen(t)
	k, K, err := NewWitness()
	if err != nil {
		t.Fatal(err)
	}
	m := digest(t, "extract recovers witness")
	ps, err := PreSign(d, m, K)
	if err != nil {
		t.Fatal(err)
	}
	got := Extract(ps, Adapt(ps, k))
	if got.Cmp(k) != 0 {
		t.Fatalf("extracted witness mismatch: got %x want %x", got, k)
	}
}

// TestAdaptWrongWitness: property (iv) — adapting with a wrong witness yields
// a signature that Verify rejects.
func TestAdaptWrongWitness(t *testing.T) {
	d, P := mustKeyGen(t)
	_, K, err := NewWitness()
	if err != nil {
		t.Fatal(err)
	}
	kWrong, _, err := NewWitness()
	if err != nil {
		t.Fatal(err)
	}
	m := digest(t, "adapt with wrong witness")
	ps, err := PreSign(d, m, K)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(P, m, Adapt(ps, kWrong)) {
		t.Fatal("signature adapted with wrong witness accepted")
	}
}

// TestVerifyPreSigNegative: VerifyPreSig rejects a wrong statement, message,
// or shat — the buyer-side gate before activating payment.
func TestVerifyPreSigNegative(t *testing.T) {
	d, P := mustKeyGen(t)
	_, K, err := NewWitness()
	if err != nil {
		t.Fatal(err)
	}
	m := digest(t, "verify presig negative")
	ps, err := PreSign(d, m, K)
	if err != nil {
		t.Fatal(err)
	}
	_, K2, err := NewWitness()
	if err != nil {
		t.Fatal(err)
	}
	if VerifyPreSig(P, m, K2, ps) {
		t.Fatal("pre-signature accepted under wrong statement K")
	}
	m2 := m
	m2[31] ^= 0x80
	if VerifyPreSig(P, m2, K, ps) {
		t.Fatal("pre-signature accepted under modified message")
	}
	shatBad := new(big.Int).Add(ps.Shat, big.NewInt(1))
	shatBad.Mod(shatBad, n)
	if VerifyPreSig(P, m, K, PreSig{R: ps.R, Shat: shatBad}) {
		t.Fatal("pre-signature accepted with modified shat")
	}
}

// TestOnChainAccessors sanity-checks the encodings the Solidity verifier
// consumes: Px < n, yParity in {0,1}, addr(R) consistent, s/e canonical.
func TestOnChainAccessors(t *testing.T) {
	d, P := mustKeyGen(t)
	m := digest(t, "onchain accessors")
	sig, err := Sign(d, m)
	if err != nil {
		t.Fatal(err)
	}
	px := PxBytes(P)
	if new(big.Int).SetBytes(px[:]).Cmp(n) >= 0 {
		t.Fatal("Px >= n despite KeyGen guard")
	}
	if yp := YParity(P); yp != 0 && yp != 1 {
		t.Fatalf("yParity = %d", yp)
	}
	if sig.AddrR() != AddrOfPoint(sig.R) {
		t.Fatal("AddrR mismatch")
	}
	sb := sig.SBytes()
	if new(big.Int).SetBytes(sb[:]).Cmp(sig.S) != 0 {
		t.Fatal("SBytes does not round-trip s")
	}
	eb := EBytes(P, sig.AddrR(), m)
	if new(big.Int).SetBytes(eb[:]).Cmp(Challenge(P, AddrOfPoint(sig.R), m)) != 0 {
		t.Fatal("EBytes does not match Challenge")
	}
}

// TestChallengeDomain: the challenge must bind P (both coordinates via
// parity), addr(R) and m — flipping any input changes e.
func TestChallengeDomain(t *testing.T) {
	_, P := mustKeyGen(t)
	_, R := mustKeyGen(t)
	m := digest(t, "challenge domain")
	e := Challenge(P, AddrOfPoint(R), m)
	_, R2 := mustKeyGen(t)
	if e.Cmp(Challenge(P, AddrOfPoint(R2), m)) == 0 {
		t.Fatal("challenge did not bind addr(R)")
	}
	m2 := m
	m2[5] ^= 0xff
	if e.Cmp(Challenge(P, AddrOfPoint(R), m2)) == 0 {
		t.Fatal("challenge did not bind m")
	}
	_, P2 := mustKeyGen(t)
	if e.Cmp(Challenge(P2, AddrOfPoint(R), m)) == 0 {
		t.Fatal("challenge did not bind P")
	}
}

// --- micro-benchmark (settlement-side crypto is negligible next to HE) --

// medianNanos returns the median per-op wall-clock nanoseconds over reps
// samples after warmup (warmup
// excluded, median reported). The Windows monotonic clock tick can be far
// coarser than a single curve operation, so each sample times a calibrated
// batch of calls (>= minBatch wall time) and divides by the batch size.
func medianNanos(reps, warmup int, f func()) int64 {
	const minBatch = 5 * time.Millisecond
	for i := 0; i < warmup; i++ {
		f()
	}
	batch := 1
	for {
		t0 := time.Now()
		for i := 0; i < batch; i++ {
			f()
		}
		if time.Since(t0) >= minBatch || batch >= 1<<20 {
			break
		}
		batch *= 2
	}
	ds := make([]int64, reps)
	for i := range ds {
		t0 := time.Now()
		for j := 0; j < batch; j++ {
			f()
		}
		ds[i] = time.Since(t0).Nanoseconds() / int64(batch)
	}
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return ds[reps/2]
}

// appendJSONL appends one {"op":..., "ns_median":...} line per measurement to
// the (gitignored) results file at the repo root.
func appendJSONL(t *testing.T, relPath string, rows []map[string]interface{}) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(relPath), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(relPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
}

// TestMicroBench measures KeyGen/Sign/Verify/PreSign/Adapt/Extract medians
// (>=100 reps each, warmup 10) and appends them to results/adaptor.jsonl.
func TestMicroBench(t *testing.T) {
	const reps, warmup = 128, 10
	d, P := mustKeyGen(t)
	k, K, err := NewWitness()
	if err != nil {
		t.Fatal(err)
	}
	m := digest(t, "adaptor micro bench")
	sig, err := Sign(d, m)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := PreSign(d, m, K)
	if err != nil {
		t.Fatal(err)
	}
	adapted := Adapt(ps, k)

	var okSink bool
	var sigSink Sig
	var kSink *big.Int
	rows := []map[string]interface{}{
		{"op": "KeyGen", "ns_median": medianNanos(reps, warmup, func() {
			dd, _, err := KeyGen()
			if err != nil {
				t.Fatal(err)
			}
			okSink = dd != nil
		})},
		{"op": "Sign", "ns_median": medianNanos(reps, warmup, func() {
			s, err := Sign(d, m)
			if err != nil {
				t.Fatal(err)
			}
			sigSink = s
		})},
		{"op": "Verify", "ns_median": medianNanos(reps, warmup, func() {
			okSink = Verify(P, m, sig)
		})},
		{"op": "PreSign", "ns_median": medianNanos(reps, warmup, func() {
			p, err := PreSign(d, m, K)
			if err != nil {
				t.Fatal(err)
			}
			sigSink = Sig{R: p.R, S: p.Shat}
		})},
		{"op": "Adapt", "ns_median": medianNanos(reps, warmup, func() {
			sigSink = Adapt(ps, k)
		})},
		{"op": "Extract", "ns_median": medianNanos(reps, warmup, func() {
			kSink = Extract(ps, adapted)
		})},
	}
	if !okSink && sigSink.S == nil && kSink == nil {
		t.Log("sink") // keep the sinks alive
	}
	appendJSONL(t, filepath.Join("..", "..", "results", "adaptor.jsonl"), rows)
	for _, r := range rows {
		t.Logf("%-8s median %8.1f us", r["op"], float64(r["ns_median"].(int64))/1e3)
	}
}

// TestRandomizedRoundtrips fuzzes the full adaptor cycle with random keys,
// witnesses and messages.
func TestRandomizedRoundtrips(t *testing.T) {
	for i := 0; i < 16; i++ {
		d, P := mustKeyGen(t)
		k, K, err := NewWitness()
		if err != nil {
			t.Fatal(err)
		}
		var m [32]byte
		if _, err := rand.Read(m[:]); err != nil {
			t.Fatal(err)
		}
		ps, err := PreSign(d, m, K)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyPreSig(P, m, K, ps) {
			t.Fatalf("iter %d: pre-signature rejected", i)
		}
		sig := Adapt(ps, k)
		if !Verify(P, m, sig) {
			t.Fatalf("iter %d: adapted signature rejected", i)
		}
		if Extract(ps, sig).Cmp(k) != 0 {
			t.Fatalf("iter %d: witness mismatch", i)
		}
	}
}
