package blob

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"fairhe/pkg/hashes"

	"github.com/ethereum/go-ethereum/crypto/kzg4844"
)

// TestPackBytes: byte strings of every boundary size round-trip through the
// blobs, take the expected number of blobs, and every element stays below
// r_bls.
func TestPackBytes(t *testing.T) {
	r := hashes.BLSModulus()
	for _, n := range []int{0, 1, 31, 32, 33, Capacity - 1, Capacity, Capacity + 1, 2*Capacity + 1000} {
		data := make([]byte, n)
		rand.Read(data)
		for i := 0; i < n && i < 64; i++ {
			data[i] = 0xff // the top bits of the first elements set
		}
		blobs := PackBytes(data)
		want := (n + Capacity - 1) / Capacity
		if want == 0 {
			want = 1
		}
		if len(blobs) != want || Count(n) != want {
			t.Fatalf("%d bytes: %d blobs, want %d", n, len(blobs), want)
		}
		for b := range blobs {
			for _, e := range Elements(&blobs[b], 4096) {
				if e.Cmp(r) >= 0 {
					t.Fatalf("%d bytes: element not below r_bls", n)
				}
			}
		}
		back, err := UnpackBytes(blobs, n)
		if err != nil || !bytes.Equal(back, data) {
			t.Fatalf("%d bytes: round trip failed (%v)", n, err)
		}
	}
	if _, err := UnpackBytes(make([]kzg4844.Blob, 1), Capacity+1); err == nil {
		t.Fatal("more bytes than the blobs hold were read")
	}
	if Capacity != 130048 {
		t.Fatalf("capacity %d", Capacity)
	}
}

// TestSidecarAndCheck: the sidecar of two blobs carries their versioned
// hashes, each blob checks against its own, and a changed blob fails.
func TestSidecarAndCheck(t *testing.T) {
	data := make([]byte, Capacity+100)
	rand.Read(data)
	blobs := PackBytes(data)
	sc, err := NewSidecar(blobs)
	if err != nil {
		t.Fatal(err)
	}
	vhs := sc.BlobHashes()
	if len(vhs) != 2 || len(sc.Proofs) != 2*kzg4844.CellProofsPerBlob {
		t.Fatalf("sidecar of %d hashes and %d proofs", len(vhs), len(sc.Proofs))
	}
	for i := range blobs {
		com, _ := kzg4844.BlobToCommitment(&blobs[i])
		if kzg4844.CalcBlobHashV1(sha256.New(), &com) != vhs[i] {
			t.Fatal("versioned hash out of order")
		}
		if err := Check(&blobs[i], vhs[i]); err != nil {
			t.Fatal(err)
		}
	}
	if Check(&blobs[0], vhs[1]) == nil {
		t.Fatal("a blob checked against another's versioned hash")
	}
	changed := blobs[1]
	new(big.Int).SetInt64(7).FillBytes(changed[32*5 : 32*6])
	if Check(&changed, vhs[1]) == nil {
		t.Fatal("a changed blob passed")
	}
}
