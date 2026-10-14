// Package blob carries the Case 1 deliverable as EIP-4844 blob data
// (paper Section 4.3 and Appendix C.5): the deliverable's coefficients
// packed into the blob's leading field
// elements, the KZG commitment and versioned hash, the evaluation point
// z = H_pt(vh || h_D), the opening at z, and the version-1 sidecar (cell
// proofs) that the Osaka rules of the simulated chain require. The buyer's
// side recovers D from the sidecar and checks it against the claimed
// versioned hash.
package blob

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"fairhe/pkg/hashes"
	"fairhe/pkg/zk/gadgets"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
)

// FromElements returns the blob whose first elements are elems (each below
// r_bls, 32-byte big-endian) and whose other elements are zero.
func FromElements(elems []*big.Int) (*kzg4844.Blob, error) {
	if len(elems) > gadgets.BlobWidth {
		return nil, fmt.Errorf("blob: %d elements exceed a blob", len(elems))
	}
	r := hashes.BLSModulus()
	var b kzg4844.Blob
	for i, e := range elems {
		if e.Sign() < 0 || e.Cmp(r) >= 0 {
			return nil, fmt.Errorf("blob: element %d is not a field element", i)
		}
		e.FillBytes(b[32*i : 32*i+32])
	}
	return &b, nil
}

// Elements returns the first k elements of a blob.
func Elements(b *kzg4844.Blob, k int) []*big.Int {
	out := make([]*big.Int, k)
	for i := range out {
		out[i] = new(big.Int).SetBytes(b[32*i : 32*i+32])
	}
	return out
}

// Link is the blob of a claim with the values the contract checks.
type Link struct {
	Blob       *kzg4844.Blob
	Commitment kzg4844.Commitment
	VH         [32]byte // versioned hash, as blobhash(0) returns it
	HD         [32]byte // digest h_D of the deliverable
	Z, Y       *big.Int // z = H_pt(vh || h_D) and the blob polynomial's value at z
	Proof      kzg4844.Proof
}

// NewLink builds the blob of the packed deliverable elems with digest hD,
// derives z as the contract does, and opens the commitment at z. The value
// y equals the barycentric evaluation that pi_eval proves.
func NewLink(elems []*big.Int, hD [32]byte) (*Link, error) {
	b, err := FromElements(elems)
	if err != nil {
		return nil, err
	}
	com, err := kzg4844.BlobToCommitment(b)
	if err != nil {
		return nil, err
	}
	vh := kzg4844.CalcBlobHashV1(sha256.New(), &com)
	z := hashes.Pt(vh, hD)
	var point kzg4844.Point
	z.FillBytes(point[:])
	proof, claim, err := kzg4844.ComputeProof(b, point)
	if err != nil {
		return nil, err
	}
	y := new(big.Int).SetBytes(claim[:])
	if ref, err := gadgets.BlobEvalNative(elems, z); err != nil || ref.Cmp(y) != 0 {
		return nil, errors.New("blob: KZG claim differs from the barycentric evaluation")
	}
	return &Link{Blob: b, Commitment: com, VH: vh, HD: hD, Z: z, Y: y, Proof: proof}, nil
}

// Sidecar returns the version-1 sidecar of the link's blob (128 cell proofs).
func (l *Link) Sidecar() (*types.BlobTxSidecar, error) {
	cells, err := kzg4844.ComputeCellProofs(l.Blob)
	if err != nil {
		return nil, err
	}
	return types.NewBlobTxSidecar(types.BlobSidecarVersion1, []kzg4844.Blob{*l.Blob},
		[]kzg4844.Commitment{l.Commitment}, cells), nil
}

// Retrieve is the buyer's side: it checks that the sidecar's blob hashes to
// the versioned hash of the claim and returns its first k elements.
func Retrieve(sc *types.BlobTxSidecar, vh [32]byte, k int) ([]*big.Int, error) {
	if sc == nil || len(sc.Blobs) != 1 || len(sc.Commitments) != 1 {
		return nil, errors.New("blob: expected one blob")
	}
	com, err := kzg4844.BlobToCommitment(&sc.Blobs[0])
	if err != nil {
		return nil, err
	}
	if com != sc.Commitments[0] || kzg4844.CalcBlobHashV1(sha256.New(), &com) != vh {
		return nil, errors.New("blob: blob does not match the claimed versioned hash")
	}
	return Elements(&sc.Blobs[0], k), nil
}

// Unpack splits packed elements back into count values of
// bits bits, per values per element.
func Unpack(elems []*big.Int, bits, per, count int) ([]*big.Int, error) {
	out := make([]*big.Int, 0, count)
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(bits)), big.NewInt(1))
	for _, e := range elems {
		v := new(big.Int).Set(e)
		for i := 0; i < per && len(out) < count; i++ {
			out = append(out, new(big.Int).And(v, mask))
			v.Rsh(v, uint(bits))
		}
	}
	if len(out) != count {
		return nil, fmt.Errorf("blob: %d values unpacked, want %d", len(out), count)
	}
	return out, nil
}
