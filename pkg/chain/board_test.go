package chain_test

import (
	"crypto/rand"
	"path/filepath"
	"testing"

	"fairhe/pkg/blob"
	"fairhe/pkg/chain"
	"fairhe/pkg/onchain"
)

// TestBlobBoard (option O6): a type-3 transaction posts two digests over
// three blobs and the events record each digest with the versioned hashes
// of its blobs and the poster; a transaction whose counts leave a blob
// unnamed, name a missing blob, contain a zero or do not match the digests
// reverts.
func TestBlobBoard(t *testing.T) {
	if testing.Short() {
		t.Skip("needs the compiled BlobBoard")
	}
	alice, _ := chain.NewAccount()
	bob, _ := chain.NewAccount()
	env, err := chain.NewEnv(alice, bob)
	if err != nil {
		t.Fatal(err)
	}
	defer env.Close()
	root, _ := onchain.RepoRoot()
	con, err := chain.LoadContract(filepath.Join(root, "contracts", "out", "BlobBoard.json"))
	if err != nil {
		t.Fatalf("%v (compile with: python scripts/compile_sol.py contracts/BlobBoard.sol contracts/out/BlobBoard.json BlobBoard)", err)
	}
	board, rcpt, err := chain.DeployBoard(env, alice, con)
	ok(t, rcpt, err, "deploy")
	t.Logf("deploy: %d gas", rcpt.GasUsed)

	data := make([]byte, 2*blob.Capacity+10)
	rand.Read(data)
	blobs := blob.PackBytes(data) // three blobs
	sc, err := blob.NewSidecar(blobs)
	if err != nil {
		t.Fatal(err)
	}
	vhs := sc.BlobHashes()
	d1, d2 := [32]byte{1}, [32]byte{2}
	rcpt, err = board.Post(alice, [][32]byte{d1, d2}, []uint8{1, 2}, sc)
	ok(t, rcpt, err, "post of two digests over three blobs")
	t.Logf("post: %d gas, %d blob gas", rcpt.GasUsed, rcpt.BlobGasUsed)
	p1, err := board.Postings(alice.Addr, d1)
	if err != nil || len(p1) != 1 || len(p1[0].VHs) != 1 || p1[0].VHs[0] != vhs[0] {
		t.Fatalf("postings of d1: %+v %v", p1, err)
	}
	p2, _ := board.Postings(alice.Addr, d2)
	if len(p2) != 1 || len(p2[0].VHs) != 2 || p2[0].VHs[0] != vhs[1] || p2[0].VHs[1] != vhs[2] {
		t.Fatalf("postings of d2: %+v", p2)
	}
	if p2[0].Block != rcpt.BlockNumber.Uint64() {
		t.Fatal("posting block differs from the receipt's")
	}
	if p, _ := board.Postings(bob.Addr, d1); len(p) != 0 {
		t.Fatal("a posting attributed to another poster")
	}

	for _, c := range []struct {
		what    string
		digests [][32]byte
		counts  []uint8
	}{
		{"a blob left unnamed", [][32]byte{d1, d2}, []uint8{1, 1}},
		{"a missing blob named", [][32]byte{d1, d2}, []uint8{2, 2}},
		{"a zero count", [][32]byte{d1, d2, d1}, []uint8{1, 0, 2}},
		{"counts that do not match the digests", [][32]byte{d1}, []uint8{1, 2}},
	} {
		sc, _ := blob.NewSidecar(blob.PackBytes(data))
		rcpt, err := board.Post(bob, c.digests, c.counts, sc)
		reverts(t, rcpt, err, c.what)
	}
}
