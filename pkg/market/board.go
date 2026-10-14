package market

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"fairhe/pkg/blob"
	"fairhe/pkg/chain"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/params"
)

// Board carries the bulky values of registration and orders, each with its
// proof, under the digest that the ledger records for the value: the DA
// layer or blob data (option O6). The counterparty checks a
// fetched value against the digest and verifies the proof; a value it
// cannot fetch makes it reject the order (seller) or not order (buyer).
type Board interface {
	// Post publishes items for from and returns the receipts of the
	// transactions it sent (none for the DA layer).
	Post(from *chain.Account, items ...Item) ([]*types.Receipt, error)
	// Fetch returns the value and proof that poster published under digest.
	Fetch(poster common.Address, digest [32]byte, label string) (value, proof []byte, err error)
}

// Item is a bulky value with its proof, under the digest of the value.
type Item struct {
	Digest       [32]byte
	Label        string // the proof's label
	Value, Proof []byte
}

// ErrUnavailable reports a value or proof that cannot be fetched.
var ErrUnavailable = errors.New("unavailable")

// payload is an item as posted in blobs: the lengths of the value and the
// proof (4 bytes each, big-endian), the value, the proof.
func (it Item) payload() []byte {
	out := make([]byte, 8, 8+len(it.Value)+len(it.Proof))
	binary.BigEndian.PutUint32(out[0:4], uint32(len(it.Value)))
	binary.BigEndian.PutUint32(out[4:8], uint32(len(it.Proof)))
	return append(append(out, it.Value...), it.Proof...)
}

func parsePayload(b []byte) (value, proof []byte, err error) {
	if len(b) < 8 {
		return nil, nil, errors.New("market: short payload")
	}
	nv, np := int(binary.BigEndian.Uint32(b[0:4])), int(binary.BigEndian.Uint32(b[4:8]))
	if nv > len(b)-8 || np > len(b)-8-nv {
		return nil, nil, errors.New("market: payload lengths exceed its blobs")
	}
	return b[8 : 8+nv], b[8+nv : 8+nv+np], nil
}

// BlobBoard posts the bulky values as blob data (option O6). Each item's
// payload fills whole blobs, 254 bits per element; the items go out in
// type-3 transactions of at most params.BlobTxMaxBlobs blobs that call
// BlobBoard.post, so the ledger records each digest with the versioned
// hashes of its blobs and the poster. Fetch takes the poster's latest
// posting of a digest whose blobs the network still holds, checks each blob
// against its versioned hash and returns the value and proof. Values live
// for the retention window W after their posting, so an offer or a key
// older than W must be posted again.
type BlobBoard struct {
	B   *chain.Board
	Net *BlobNet
	// Tamper, when set, edits each item before it is posted (tests).
	Tamper func(*Item)

	mu    sync.Mutex
	stats map[postKey]PostStat
}

type postKey struct {
	poster common.Address
	digest [32]byte
}

// PostStat is the size of one posted item: payload bytes and blobs.
type PostStat struct{ Bytes, Blobs int }

// NewBlobBoard returns a board over a deployed BlobBoard and the network.
func NewBlobBoard(b *chain.Board, net *BlobNet) *BlobBoard {
	return &BlobBoard{B: b, Net: net, stats: map[postKey]PostStat{}}
}

// Stat returns the size of the latest item that poster posted under digest.
func (bb *BlobBoard) Stat(poster common.Address, digest [32]byte) (PostStat, bool) {
	bb.mu.Lock()
	defer bb.mu.Unlock()
	s, ok := bb.stats[postKey{poster, digest}]
	return s, ok
}

// Post packs the items into blobs and sends them, filling each transaction
// up to params.BlobTxMaxBlobs blobs.
func (bb *BlobBoard) Post(from *chain.Account, items ...Item) ([]*types.Receipt, error) {
	var rcpts []*types.Receipt
	var digests [][32]byte
	var counts []uint8
	var blobs []kzg4844.Blob
	flush := func() error {
		if len(digests) == 0 {
			return nil
		}
		sc, err := blob.NewSidecar(blobs)
		if err != nil {
			return err
		}
		rcpt, err := bb.B.Post(from, digests, counts, sc)
		if err != nil {
			return err
		}
		rcpts = append(rcpts, rcpt)
		if rcpt.Status != types.ReceiptStatusSuccessful {
			return errors.New("market: post reverted")
		}
		bb.Net.Publish(sc, rcpt.BlockNumber.Uint64())
		digests, counts, blobs = nil, nil, nil
		return nil
	}
	for _, it := range items {
		if bb.Tamper != nil {
			it.Value, it.Proof = append([]byte(nil), it.Value...), append([]byte(nil), it.Proof...)
			bb.Tamper(&it)
		}
		pl := it.payload()
		bs := blob.PackBytes(pl)
		if len(bs) > params.BlobTxMaxBlobs {
			return rcpts, fmt.Errorf("market: an item of %d bytes needs %d blobs, more than a transaction holds", len(pl), len(bs))
		}
		if len(blobs)+len(bs) > params.BlobTxMaxBlobs {
			if err := flush(); err != nil {
				return rcpts, err
			}
		}
		digests, counts, blobs = append(digests, it.Digest), append(counts, uint8(len(bs))), append(blobs, bs...)
		bb.mu.Lock()
		bb.stats[postKey{from.Addr, it.Digest}] = PostStat{Bytes: len(pl), Blobs: len(bs)}
		bb.mu.Unlock()
	}
	return rcpts, flush()
}

// Fetch returns the value and proof of the poster's latest posting of
// digest whose blobs are retained and match their versioned hashes.
func (bb *BlobBoard) Fetch(poster common.Address, digest [32]byte, _ string) ([]byte, []byte, error) {
	ps, err := bb.B.Postings(poster, digest)
	if err != nil {
		return nil, nil, err
	}
	now, err := bb.B.Env.BlockNumber()
	if err != nil {
		return nil, nil, err
	}
	for i := len(ps) - 1; i >= 0; i-- {
		bs := make([]kzg4844.Blob, 0, len(ps[i].VHs))
		for _, vh := range ps[i].VHs {
			b, ok := bb.Net.Fetch(vh, now)
			if !ok || blob.Check(b, vh) != nil {
				break
			}
			bs = append(bs, *b)
		}
		if len(bs) != len(ps[i].VHs) {
			continue
		}
		raw, err := blob.UnpackBytes(bs, len(bs)*blob.Capacity)
		if err != nil {
			continue
		}
		if v, p, err := parsePayload(raw); err == nil {
			return v, p, nil
		}
	}
	if len(ps) == 0 {
		return nil, nil, fmt.Errorf("value not posted: %w", ErrUnavailable)
	}
	return nil, nil, fmt.Errorf("value past the retention window or not retrievable: %w", ErrUnavailable)
}
