package blob

// Blob tests off chain (test IDs as in docs/tests.md), on full-size
// Case 1 deliverables: F1 (packing round trip, every element
// below r_bls), the versioned hash and evaluation point that F3 compares
// with the contract, the KZG opening, the version-1 sidecar with cell
// proofs that F5 sends, and the buyer's retrieval of F6. F2 is
// pkg/zk/gadgets TestF2BlobEvalMatchesKZG; F3-F6 on chain are pkg/chain
// TestMarketCase1.

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"fairhe/pkg/hashes"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
)

func deliverable(t *testing.T, n, bits int) []*big.Int {
	t.Helper()
	top := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	d := make([]*big.Int, n)
	for i := range d {
		d[i], _ = rand.Int(rand.Reader, top)
	}
	return d
}

// TestF1Packing packs the Case 1 deliverables of both schemes (8193
// coefficients of 68 bits, 3 per element, and of 43 bits, 5 per element)
// into a blob and back.
func TestF1Packing(t *testing.T) {
	for _, tc := range []struct{ bits, want int }{{68, 2731}, {43, 1639}} {
		D := deliverable(t, 8193, tc.bits)
		elems, err := hashes.PackBits(hashes.BLS12381, D, tc.bits)
		if err != nil {
			t.Fatal(err)
		}
		if len(elems) != tc.want {
			t.Fatalf("F1: %d elements of %d-bit coefficients, want %d", len(elems), tc.bits, tc.want)
		}
		b, err := FromElements(elems)
		if err != nil {
			t.Fatal(err)
		}
		got := Elements(b, len(elems))
		for i, e := range got {
			if e.Cmp(hashes.BLSModulus()) >= 0 || e.Cmp(elems[i]) != 0 {
				t.Fatalf("F1: element %d not canonical or changed", i)
			}
		}
		back, err := Unpack(got, tc.bits, hashes.PackPerElement(hashes.BLS12381, tc.bits), len(D))
		if err != nil {
			t.Fatal(err)
		}
		for i := range D {
			if back[i].Cmp(D[i]) != 0 {
				t.Fatalf("F1: coefficient %d differs after the round trip", i)
			}
		}
	}
}

func TestBlobLink(t *testing.T) {
	const n, bits = 8193, 68
	D := deliverable(t, n, bits)
	elems, err := hashes.PackBits(hashes.BLS12381, D, bits)
	if err != nil {
		t.Fatal(err)
	}
	hD, err := hashes.Dig(hashes.BLS12381, "h_D", elems)
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewLink(elems, hashes.Bytes32(hD))
	if err != nil {
		t.Fatal(err)
	}
	// The versioned hash is 0x01 || sha256(commitment)[1:] (F3 compares it
	// with the contract's blobhash(0)).
	h := sha256.Sum256(l.Commitment[:])
	if l.VH[0] != 0x01 || string(l.VH[1:]) != string(h[1:]) {
		t.Fatal("F3: versioned hash")
	}
	// z as the contract computes it: keccak256(tag || vh || h_D) mod r_bls.
	z := new(big.Int).SetBytes(crypto.Keccak256([]byte(hashes.TagPt), l.VH[:], l.HD[:]))
	z.Mod(z, hashes.BLSModulus())
	if z.Cmp(l.Z) != 0 {
		t.Fatal("evaluation point differs from the contract's")
	}
	// The opening verifies at (z, y), and not at another y.
	var point kzg4844.Point
	var claim kzg4844.Claim
	l.Z.FillBytes(point[:])
	l.Y.FillBytes(claim[:])
	if err := kzg4844.VerifyProof(l.Commitment, point, claim, l.Proof); err != nil {
		t.Fatalf("opening: %v", err)
	}
	claim[31] ^= 1
	if kzg4844.VerifyProof(l.Commitment, point, claim, l.Proof) == nil {
		t.Fatal("a wrong value verifies")
	}
	// F5, F6: the version-1 sidecar's cell proofs verify, and the buyer
	// recovers D from it.
	sc, err := l.Sidecar()
	if err != nil {
		t.Fatal(err)
	}
	if err := kzg4844.VerifyCellProofs(sc.Blobs, sc.Commitments, sc.Proofs); err != nil {
		t.Fatalf("F5: %v", err)
	}
	got, err := Retrieve(sc, l.VH, len(elems))
	if err != nil {
		t.Fatal(err)
	}
	back, err := Unpack(got, bits, hashes.PackPerElement(hashes.BLS12381, bits), n)
	if err != nil {
		t.Fatal(err)
	}
	for i := range D {
		if back[i].Cmp(D[i]) != 0 {
			t.Fatalf("F6: coefficient %d differs after retrieval", i)
		}
	}
	var other [32]byte
	other[0] = 1
	if _, err := Retrieve(sc, other, len(elems)); err == nil {
		t.Fatal("Retrieve accepted a blob under another versioned hash")
	}
}
