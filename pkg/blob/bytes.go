package blob

// Byte packing for the bulky values that option O6 posts as blob data (keys
// and ciphertexts with their proofs), and the sidecar and check of several
// blobs.

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"fairhe/pkg/zk/gadgets"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
)

// ElementBits is the payload of one blob element when bytes are packed: the
// two leading bits of each 32-byte element stay zero, so every element is
// below r_bls.
const ElementBits = 254

// Capacity is the payload of one blob in bytes (130,048).
const Capacity = gadgets.BlobWidth * ElementBits / 8

// Count returns the number of blobs that n bytes take.
func Count(n int) int { return max(1, (n+Capacity-1)/Capacity) }

// PackBytes spreads data over Count(len(data)) blobs, ElementBits bits per
// element and most significant bit first; the rest of the last blob is zero.
func PackBytes(data []byte) []kzg4844.Blob {
	out := make([]kzg4844.Blob, Count(len(data)))
	for g := 0; g < 8*len(data); g++ {
		if data[g/8]>>(7-g%8)&1 == 1 {
			b, off, mask := bitAt(g)
			out[b][off] |= mask
		}
	}
	return out
}

// UnpackBytes reads n bytes packed by PackBytes.
func UnpackBytes(blobs []kzg4844.Blob, n int) ([]byte, error) {
	if n < 0 || n > len(blobs)*Capacity {
		return nil, fmt.Errorf("blob: %d bytes do not fit in %d blobs", n, len(blobs))
	}
	out := make([]byte, n)
	for g := 0; g < 8*n; g++ {
		b, off, mask := bitAt(g)
		if blobs[b][off]&mask != 0 {
			out[g/8] |= 1 << (7 - g%8)
		}
	}
	return out, nil
}

// bitAt locates payload bit g: its blob, its byte in the blob and the mask.
func bitAt(g int) (int, int, byte) {
	e, j := g/ElementBits, g%ElementBits
	pos := 256 - ElementBits + j // bit of the 32-byte element, from the top
	return e / gadgets.BlobWidth, 32*(e%gadgets.BlobWidth) + pos/8, byte(1) << (7 - pos%8)
}

// NewSidecar returns the version-1 sidecar (commitments and cell proofs) of
// blobs.
func NewSidecar(blobs []kzg4844.Blob) (*types.BlobTxSidecar, error) {
	coms := make([]kzg4844.Commitment, len(blobs))
	var proofs []kzg4844.Proof
	for i := range blobs {
		c, err := kzg4844.BlobToCommitment(&blobs[i])
		if err != nil {
			return nil, err
		}
		cells, err := kzg4844.ComputeCellProofs(&blobs[i])
		if err != nil {
			return nil, err
		}
		coms[i], proofs = c, append(proofs, cells...)
	}
	return types.NewBlobTxSidecar(types.BlobSidecarVersion1, blobs, coms, proofs), nil
}

// Check reports whether a blob hashes to the versioned hash vh, with its
// KZG commitment recomputed from the blob.
func Check(b *kzg4844.Blob, vh [32]byte) error {
	com, err := kzg4844.BlobToCommitment(b)
	if err != nil {
		return err
	}
	if kzg4844.CalcBlobHashV1(sha256.New(), &com) != vh {
		return errors.New("blob: blob does not match its versioned hash")
	}
	return nil
}
