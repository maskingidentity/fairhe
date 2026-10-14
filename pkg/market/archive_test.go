package market

import (
	"crypto/rand"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"fairhe/pkg/blob"
	"fairhe/pkg/hashes"
	"fairhe/pkg/zk/zkmeasure"

	"github.com/ethereum/go-ethereum/crypto/kzg4844"
)

// TestO7ArchiveCost measures the archive's work per claim (opt-in,
// FAIRHE_RECORD=1): the check of a blob against its versioned hash alone,
// storing it as Sync does (fetch from the network, check, write) and
// reading it back with the check, each as the mean over 200 runs, since
// one run takes a few milliseconds, about the resolution of the clock. The
// row goes to results/v8/archive.jsonl.
func TestO7ArchiveCost(t *testing.T) {
	if os.Getenv("FAIRHE_RECORD") == "" {
		t.Skip("set FAIRHE_RECORD=1")
	}
	const reps = 200
	elems := make([]*big.Int, 4096)
	for i := range elems {
		elems[i], _ = rand.Int(rand.Reader, hashes.BLSModulus())
	}
	b, err := blob.FromElements(elems)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := blob.NewSidecar([]kzg4844.Blob{*b})
	if err != nil {
		t.Fatal(err)
	}
	vh := sc.BlobHashes()[0]
	net := NewBlobNet(RetentionBlocks)
	net.Publish(sc, 1)
	arch, err := OpenArchive(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mean := func(f func() error) float64 {
		start := time.Now()
		for i := 0; i < reps; i++ {
			if err := f(); err != nil {
				t.Fatal(err)
			}
		}
		return 1000 * time.Since(start).Seconds() / reps
	}
	check := mean(func() error { return blob.Check(b, vh) })
	store := mean(func() error {
		bl, ok := net.Fetch(vh, 2)
		if !ok {
			return os.ErrNotExist
		}
		if err := blob.Check(bl, vh); err != nil {
			return err
		}
		return writeAtomic(arch.path(vh), bl[:])
	})
	read := mean(func() error {
		bl, ok := arch.Fetch(vh)
		if !ok {
			return os.ErrNotExist
		}
		return blob.Check(bl, vh)
	})
	row := map[string]any{"time": time.Now().UTC().Format(time.RFC3339), "reps": reps, "blob_bytes": len(kzg4844.Blob{}),
		"check_ms": check, "store_ms": store, "read_ms": read, "git_commit": zkmeasure.GitCommit()}
	if err := zkmeasure.AppendJSON("archive.jsonl", row); err != nil {
		t.Fatal(err)
	}
	t.Logf("per claim: check %.2f ms, store %.2f ms, read and check %.2f ms (means of %d)", check, store, read, reps)
}

// TestO7Archive (option O7): an archive that syncs while the claim's blob
// is retained serves it after the retention window W, when the network no
// longer does; the buyer decodes from it. The archive resumes from its
// cursor after a restart, a changed archived blob fails the buyer's check
// against the versioned hash, and an archive that syncs after W misses the
// blob.
func TestO7Archive(t *testing.T) {
	w := newWorld(t, "case1_bfv")
	w.net = NewBlobNet(128)
	s := w.newSeller(t, 2, 32)
	b := w.newBuyer(t)
	dir := t.TempDir()
	arch, err := OpenArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	wts := []int64{-5, 9}
	id, _, err := b.Order(s.OfferID, 1, wts, 80)
	if err != nil {
		t.Fatal(err)
	}
	if out, why, err := s.Handle(id); err != nil || out != Claimed {
		t.Fatalf("seller: %v %s %v", out, why, err)
	}
	rep, err := arch.Sync(w.market, w.net)
	if err != nil || rep.Stored != 1 || len(rep.Missed) != 0 {
		t.Fatalf("sync: %+v %v", rep, err)
	}
	ev, _ := w.market.ClaimOf(id)
	vh := ev["versionedHash"].([32]byte)

	w.env.Mine(128)
	now, _ := w.env.BlockNumber()
	if _, ok := w.net.Fetch(vh, now); ok {
		t.Fatal("the network still serves the blob after W")
	}
	if _, err := b.Await(id); err == nil || !strings.Contains(err.Error(), "not retrievable") {
		t.Fatalf("decoded without the network or an archive (%v)", err)
	}
	b.Archive = arch
	res, err := b.Await(id)
	if err != nil {
		t.Fatal(err)
	}
	w.checkResult(t, res, wts)

	// A restarted archive resumes from its cursor and still serves the blob.
	again, err := OpenArchive(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep, err := again.Sync(w.market, w.net); err != nil || rep.Stored+rep.Held+len(rep.Missed) != 0 {
		t.Fatalf("a restarted archive rescanned old blocks: %+v %v", rep, err)
	}
	bl, ok := again.Fetch(vh)
	if !ok || blob.Check(bl, vh) != nil {
		t.Fatal("a restarted archive lost the blob")
	}
	// A changed archived blob fails the check against the versioned hash.
	raw, _ := os.ReadFile(again.path(vh))
	raw[100] ^= 1
	if err := os.WriteFile(again.path(vh), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if bl, ok := again.Fetch(vh); !ok || blob.Check(bl, vh) == nil {
		t.Fatal("a changed archived blob passed the check")
	}

	// An archive that syncs after W misses the blob of a later claim.
	id2, _, err := b.Order(s.OfferID, 2, wts, 80)
	if err != nil {
		t.Fatal(err)
	}
	if out, why, err := s.Handle(id2); err != nil || out != Claimed {
		t.Fatalf("seller: %v %s %v", out, why, err)
	}
	w.env.Mine(128)
	if rep, err := again.Sync(w.market, w.net); err != nil || rep.Stored != 0 || len(rep.Missed) != 1 {
		t.Fatalf("late sync: %+v %v", rep, err)
	}
}
