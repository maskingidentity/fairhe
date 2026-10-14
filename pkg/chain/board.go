package chain

// Driver of BlobBoard.sol (option O6): type-3 transactions that post the
// bulky values of registration and orders as blob data and record each
// digest with the versioned hashes of its blobs.

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Board wraps one deployed BlobBoard.
type Board struct {
	Env  *Env
	Con  *Contract
	Addr common.Address
}

// DeployBoard deploys a BlobBoard.
func DeployBoard(env *Env, from *Account, con *Contract) (*Board, *types.Receipt, error) {
	addr, rcpt, err := env.Deploy(from, con)
	if err != nil {
		return nil, rcpt, err
	}
	return &Board{Env: env, Con: con, Addr: addr}, rcpt, nil
}

// Post sends a type-3 transaction carrying sc that records digests[i] with
// the next counts[i] blobs of sc, in order, and mines it.
func (b *Board) Post(from *Account, digests [][32]byte, counts []uint8, sc *types.BlobTxSidecar) (*types.Receipt, error) {
	data, err := b.Con.ABI.Pack("post", digests, counts)
	if err != nil {
		return nil, fmt.Errorf("chain: pack post: %w", err)
	}
	return b.Env.SendBlobTx(from, b.Addr, data, sc, 500_000)
}

// Posting is one Posted event: its block and the versioned hashes of the
// blobs that carry the value.
type Posting struct {
	Block uint64
	VHs   [][32]byte
}

// Postings returns the postings of a digest by poster, oldest first.
func (b *Board) Postings(poster common.Address, digest [32]byte) ([]Posting, error) {
	ev := b.Con.ABI.Events["Posted"]
	logs, err := b.Env.Client.FilterLogs(context.Background(), ethereum.FilterQuery{
		Addresses: []common.Address{b.Addr},
		Topics:    [][]common.Hash{{ev.ID}, {common.BytesToHash(poster.Bytes())}, {common.Hash(digest)}},
	})
	if err != nil {
		return nil, err
	}
	out := make([]Posting, 0, len(logs))
	for _, lg := range logs {
		v, err := ev.Inputs.NonIndexed().Unpack(lg.Data)
		if err != nil {
			return nil, err
		}
		out = append(out, Posting{Block: lg.BlockNumber, VHs: v[0].([][32]byte)})
	}
	return out, nil
}
