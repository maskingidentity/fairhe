package market

import (
	"crypto/rand"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"

	"fairhe/pkg/chain"
	"fairhe/pkg/onchain"
	"fairhe/pkg/rlwe"
)

// useBlobBoard deploys a BlobBoard and makes it the world's board (option
// O6): the bulky values travel as blob data instead of the DA layer.
func (w *world) useBlobBoard(t *testing.T) *BlobBoard {
	t.Helper()
	root, _ := onchain.RepoRoot()
	con, err := chain.LoadContract(filepath.Join(root, "contracts", "out", "BlobBoard.json"))
	if err != nil {
		t.Fatalf("%v (compile with: python scripts/compile_sol.py contracts/BlobBoard.sol contracts/out/BlobBoard.json BlobBoard)", err)
	}
	b, _, err := chain.DeployBoard(w.env, w.seller, con)
	if err != nil {
		t.Fatal(err)
	}
	bb := NewBlobBoard(b, w.net)
	w.board = bb
	return bb
}

// TestPackPolys: the compact encoding of the bulky values round-trips, with
// and without a seed, and refuses a coefficient wider than its bits.
func TestPackPolys(t *testing.T) {
	for _, bits := range []int{1, 7, 43, 103, 125, 134} {
		polys := make([][]*big.Int, 2)
		for j := range polys {
			polys[j] = make([]*big.Int, 37)
			for i := range polys[j] {
				polys[j][i], _ = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
			}
			polys[j][0] = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
		}
		var seed [SeedBytes]byte
		rand.Read(seed[:])
		b, err := PackWithSeed(bits, seed, polys...)
		if err != nil || len(b) != (2*37*bits+7)/8+SeedBytes {
			t.Fatalf("%d bits: %d bytes (%v)", bits, len(b), err)
		}
		back, s2, err := UnpackWithSeed(b, bits, 37, 2)
		if err != nil || s2 != seed {
			t.Fatalf("%d bits: %v", bits, err)
		}
		for j := range polys {
			for i := range polys[j] {
				if back[j][i].Cmp(polys[j][i]) != 0 {
					t.Fatalf("%d bits: coefficient %d of %d differs", bits, i, j)
				}
			}
		}
		if _, err := PackPolys(bits, []*big.Int{new(big.Int).Lsh(big.NewInt(1), uint(bits))}); err == nil {
			t.Fatalf("%d bits: a wider coefficient was packed", bits)
		}
	}
}

// TestO6Flows: with the bulky values posted as blob data, both cases run to
// a correct result. The seller posts its Case 2 slots and the buyer its
// Case 1 key and its order input in type-3 transactions; each party reads
// the other's values from the blobs that the ledger's Posted events name.
// A posting under the order's digest by another account is ignored.
func TestO6Flows(t *testing.T) {
	for _, params := range []string{"case1_bfv", "case2_bfv"} {
		w := newWorld(t, params)
		bb := w.useBlobBoard(t)
		s := w.newSeller(t, 2, 32)
		b := w.newBuyer(t)
		if err := b.CheckOffer(s.OfferID); err != nil {
			t.Fatal(err)
		}
		wts := []int64{-5, 9}
		id, _, err := b.Order(s.OfferID, 1, wts, 80)
		if err != nil {
			t.Fatal(err)
		}
		oi, _ := w.market.OrderInfo(id)
		if _, err := bb.Post(w.seller, Item{Digest: oi.HInput, Label: "other", Value: []byte{1, 2, 3}, Proof: []byte{4}}); err != nil {
			t.Fatal(err)
		}
		out, why, err := s.Handle(id)
		if err != nil || out != Claimed {
			t.Fatalf("%s: seller: %v %s %v", params, out, why, err)
		}
		res, err := b.Await(id)
		if err != nil {
			t.Fatal(err)
		}
		w.checkResult(t, res, wts)
		st, _ := bb.Stat(w.buyer.Addr, oi.HInput)
		t.Logf("%s: order input posted as %d bytes in %d blob(s)", params, st.Bytes, st.Blobs)
	}
}

// TestO6AbortPaths: with blob data, the seller rejects an order whose
// proof fails and an order whose input was never posted under its digest.
func TestO6AbortPaths(t *testing.T) {
	w := newWorld(t, "case2_bfv")
	bb := w.useBlobBoard(t)
	s := w.newSeller(t, 2, 32)
	b := w.newBuyer(t)
	for _, c := range []struct {
		what, why string
		tamper    func(*Item)
	}{
		{"a failing pi_eval", "pi_eval fails", func(it *Item) { it.Proof[len(it.Proof)/2] ^= 1 }},
		{"an input never posted", "unavailable", func(it *Item) { it.Digest[0] ^= 1 }},
	} {
		bb.Tamper = c.tamper
		id, _, err := b.Order(s.OfferID, 1, []int64{1, 2}, 80)
		bb.Tamper = nil
		if err != nil {
			t.Fatal(err)
		}
		out, why, err := s.Handle(id)
		if err != nil || out != Rejected || !strings.Contains(why, c.why) {
			t.Fatalf("%s: expected a reject (%s), got %v %s %v", c.what, c.why, out, why, err)
		}
		t.Logf("%s: rejected: %s", c.what, why)
	}
}

// TestO6Retention: a posted value lives for the retention window W only.
// Once W blocks have passed since the slots were posted the buyer cannot
// fetch them and does not order; posted again, the slot is usable.
func TestO6Retention(t *testing.T) {
	w := newWorld(t, "case2_bfv")
	w.net = NewBlobNet(64)
	w.useBlobBoard(t)
	s := w.newSeller(t, 1, 32)
	b := w.newBuyer(t)
	if err := b.CheckOffer(s.OfferID); err != nil {
		t.Fatal(err)
	}
	w.env.Mine(64)
	if err := b.CheckOffer(s.OfferID); err == nil || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a slot past the retention window was fetched (%v)", err)
	}
	if _, _, err := s.publishSlot(s.slots[1]); err != nil {
		t.Fatal(err)
	}
	if err := b.CheckOffer(s.OfferID); err != nil {
		t.Fatalf("a posted-again slot was refused: %v", err)
	}
	if w.t.Case() != rlwe.Case2 {
		t.Fatal("unexpected case")
	}
}
