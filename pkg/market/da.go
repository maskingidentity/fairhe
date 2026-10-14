// Package market implements the parties of the fair exchange: the seller and
// buyer state machines over the settlement contract, and the boards that
// carry the bulky values (keys, ciphertexts, off-chain proofs) under the
// digests the ledger records: the data-availability layer or blob data
// (option O6).
package market

import (
	"fmt"
	"math/big"
	"sync"

	"fairhe/pkg/chain"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
)

// DA is the prototype's data-availability layer: a local store addressed by
// the digests that the ledger records. A missing value makes
// the counterparty reject (seller) or not order (buyer).
type DA struct {
	mu sync.Mutex
	m  map[[32]byte][]byte
}

// NewDA returns an empty store.
func NewDA() *DA { return &DA{m: map[[32]byte][]byte{}} }

// Put stores a value under a key.
func (d *DA) Put(key [32]byte, v []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.m[key] = append([]byte(nil), v...)
}

// Get returns the value of a key.
func (d *DA) Get(key [32]byte) ([]byte, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	v, ok := d.m[key]
	return v, ok
}

// Delete removes a key (used to simulate an unavailable value).
func (d *DA) Delete(key [32]byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.m, key)
}

// Post stores each item's value under its digest and its proof under
// ProofKey(digest, label); it sends no transaction.
func (d *DA) Post(_ *chain.Account, items ...Item) ([]*types.Receipt, error) {
	for _, it := range items {
		d.Put(it.Digest, it.Value)
		d.Put(ProofKey(it.Digest, it.Label), it.Proof)
	}
	return nil, nil
}

// Fetch returns the value and proof stored under digest (the poster is not
// needed: the store is addressed by digest).
func (d *DA) Fetch(_ common.Address, digest [32]byte, label string) ([]byte, []byte, error) {
	v, ok := d.Get(digest)
	if !ok {
		return nil, nil, fmt.Errorf("value %w", ErrUnavailable)
	}
	p, ok := d.Get(ProofKey(digest, label))
	if !ok {
		return nil, nil, fmt.Errorf("proof %w", ErrUnavailable)
	}
	return v, p, nil
}

// ProofKey is the DA key of the proof that accompanies the value under base.
func ProofKey(base [32]byte, label string) [32]byte {
	var k [32]byte
	copy(k[:], crypto.Keccak256(base[:], []byte(label)))
	return k
}

// PackPolys serialises polynomials with coefficients in [0, 2^bits), bits
// bits per coefficient, most significant bit first: the compact sizes that
// Table 4 of the paper reports.
func PackPolys(bits int, polys ...[]*big.Int) ([]byte, error) {
	total := 0
	for _, p := range polys {
		total += len(p)
	}
	out := make([]byte, (total*bits+7)/8)
	var buf [64]byte
	g := 0
	for _, p := range polys {
		for _, c := range p {
			if c.Sign() < 0 || c.BitLen() > bits || bits > 8*len(buf) {
				return nil, fmt.Errorf("market: coefficient outside [0, 2^%d)", bits)
			}
			c.FillBytes(buf[:])
			for j := 8*len(buf) - bits; j < 8*len(buf); j++ {
				if buf[j/8]>>(7-j%8)&1 == 1 {
					out[g/8] |= 1 << (7 - g%8)
				}
				g++
			}
		}
	}
	return out, nil
}

// UnpackPolys reads count polynomials of n coefficients of bits bits.
func UnpackPolys(b []byte, bits, n, count int) ([][]*big.Int, error) {
	if len(b) != (n*count*bits+7)/8 || bits > 512 {
		return nil, fmt.Errorf("market: %d bytes for %d polynomials of %d coefficients of %d bits", len(b), count, n, bits)
	}
	out := make([][]*big.Int, count)
	var buf [64]byte
	g := 0
	for j := range out {
		out[j] = make([]*big.Int, n)
		for i := range out[j] {
			clear(buf[:])
			for k := 8*len(buf) - bits; k < 8*len(buf); k++ {
				if b[g/8]>>(7-g%8)&1 == 1 {
					buf[k/8] |= 1 << (7 - k%8)
				}
				g++
			}
			out[j][i] = new(big.Int).SetBytes(buf[:])
		}
	}
	return out, nil
}

// SeedBytes is the length of the seed that stands for a uniform component.
const SeedBytes = 32

// PackWithSeed serialises polynomials as PackPolys does, followed by a seed.
func PackWithSeed(bits int, seed [SeedBytes]byte, polys ...[]*big.Int) ([]byte, error) {
	b, err := PackPolys(bits, polys...)
	return append(b, seed[:]...), err
}

// UnpackWithSeed reads count polynomials of n coefficients of bits bits and
// the seed that follows them.
func UnpackWithSeed(b []byte, bits, n, count int) ([][]*big.Int, [SeedBytes]byte, error) {
	var seed [SeedBytes]byte
	if len(b) < SeedBytes {
		return nil, seed, fmt.Errorf("market: %d bytes hold no seed", len(b))
	}
	k := len(b) - SeedBytes
	polys, err := UnpackPolys(b[:k], bits, n, count)
	copy(seed[:], b[k:])
	return polys, seed, err
}

// BlobNet stands in for the network's retention of blob data: the simulated
// backend has no blob retrieval API, so the sender of a blob transaction
// hands its sidecar over once the transaction is included, and BlobNet
// serves each blob, addressed by versioned hash, for W blocks after its
// inclusion.
type BlobNet struct {
	W  uint64
	mu sync.Mutex
	m  map[[32]byte]netBlob
}

type netBlob struct {
	blob  *kzg4844.Blob
	block uint64
}

// NewBlobNet returns a stand-in with the retention window w in blocks.
func NewBlobNet(w uint64) *BlobNet { return &BlobNet{W: w, m: map[[32]byte]netBlob{}} }

// Publish records the blobs of a transaction included in block.
func (n *BlobNet) Publish(sc *types.BlobTxSidecar, block uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for i, h := range sc.BlobHashes() {
		n.m[h] = netBlob{blob: &sc.Blobs[i], block: block}
	}
}

// Fetch returns the blob of a versioned hash if it is still retained at
// block now.
func (n *BlobNet) Fetch(vh [32]byte, now uint64) (*kzg4844.Blob, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	nb, ok := n.m[vh]
	if !ok || now >= nb.block+n.W {
		return nil, false
	}
	return nb.blob, true
}
