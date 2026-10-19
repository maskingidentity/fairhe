package chain

// Driver of the settlement contract FairExchangeMarket.sol: deployment with
// the verifiers fixed by VK ID, registration, orders, the two proof-carrying
// claims (claimBlob is sent as a type-3 transaction carrying the
// deliverable's blob), refund, reject and retire. Time is the block number;
// Mine advances it.

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// Market wraps one deployed FairExchangeMarket.
type Market struct {
	Env  *Env
	Con  *Contract
	Addr common.Address
}

// Deploy deploys a contract with constructor arguments and returns its
// address and receipt.
func (env *Env) Deploy(from *Account, con *Contract, args ...interface{}) (common.Address, *types.Receipt, error) {
	data := append([]byte{}, con.Bin...)
	if len(args) > 0 {
		packed, err := con.ABI.Pack("", args...)
		if err != nil {
			return common.Address{}, nil, fmt.Errorf("chain: pack constructor: %w", err)
		}
		data = append(data, packed...)
	}
	rcpt, err := env.SendTx(from, nil, nil, data, 0)
	if err != nil {
		return common.Address{}, nil, err
	}
	if rcpt.Status != types.ReceiptStatusSuccessful {
		return common.Address{}, rcpt, errors.New("chain: deployment reverted")
	}
	return rcpt.ContractAddress, rcpt, nil
}

// DeployMarket deploys the market with its on-chain verifiers (by VK ID)
// and the VK IDs of the off-chain proofs.
func DeployMarket(env *Env, from *Account, con *Contract, claimVks [][32]byte, verifiers []common.Address, offchainVks [][32]byte) (*Market, *types.Receipt, error) {
	addr, rcpt, err := env.Deploy(from, con, claimVks, verifiers, offchainVks)
	if err != nil {
		return nil, rcpt, err
	}
	return &Market{Env: env, Con: con, Addr: addr}, rcpt, nil
}

// Mine advances the chain by k empty blocks.
func (env *Env) Mine(k int) {
	for i := 0; i < k; i++ {
		env.Backend.Commit()
	}
}

// BlockNumber returns the current block number.
func (env *Env) BlockNumber() (uint64, error) {
	return env.Client.BlockNumber(context.Background())
}

func (m *Market) send(from *Account, value *big.Int, gasLimit uint64, method string, args ...interface{}) (*types.Receipt, error) {
	data, err := m.Con.ABI.Pack(method, args...)
	if err != nil {
		return nil, fmt.Errorf("chain: pack %s: %w", method, err)
	}
	return m.Env.SendTx(from, &m.Addr, value, data, gasLimit)
}

// Tx returns a transaction of SendInOneBlock that calls method.
func (m *Market) Tx(from *Account, value *big.Int, gasLimit uint64, tipGwei int64, method string, args ...interface{}) (TxSpec, error) {
	data, err := m.Con.ABI.Pack(method, args...)
	if err != nil {
		return TxSpec{}, fmt.Errorf("chain: pack %s: %w", method, err)
	}
	return TxSpec{From: from, To: &m.Addr, Value: value, Data: data, GasLimit: gasLimit, TipGwei: tipGwei}, nil
}

// Simulate runs method as from against the latest block without sending
// it, and returns the revert error if it would fail.
func (m *Market) Simulate(from *Account, method string, args ...interface{}) error {
	data, err := m.Con.ABI.Pack(method, args...)
	if err != nil {
		return err
	}
	_, err = m.Env.Client.CallContract(context.Background(), ethereum.CallMsg{From: from.Addr, To: &m.Addr, Data: data}, nil)
	return err
}

// OfferArgs mirrors FairExchangeMarket.OfferArgs.
type OfferArgs struct {
	CaseId  uint8
	Payout  common.Address
	ComX    [32]byte
	Price   *big.Int
	TMin    uint64
	TMax    uint64
	Q       uint16
	Terms   [32]byte
	ClaimVk [32]byte
	KeyVk   [32]byte
	InputVk [32]byte
}

// RegisterOffer registers an offer; in Case 2 hPk, hC1 and hS carry one
// digest per slot.
func (m *Market) RegisterOffer(from *Account, a OfferArgs, hPk, hC1, hS [][32]byte) (*big.Int, *types.Receipt, error) {
	if hPk == nil {
		hPk, hC1, hS = [][32]byte{}, [][32]byte{}, [][32]byte{}
	}
	rcpt, err := m.send(from, nil, 0, "registerOffer", a, hPk, hC1, hS)
	if err != nil {
		return nil, rcpt, err
	}
	id, err := m.eventUint(rcpt, "OfferRegistered")
	return id, rcpt, err
}

// RegisterKey registers a Case 1 buyer key and returns its key ID.
func (m *Market) RegisterKey(from *Account, keyIndex uint64, hPk, hSB [32]byte) ([32]byte, *types.Receipt, error) {
	rcpt, err := m.send(from, nil, 0, "registerKey", keyIndex, hPk, hSB)
	if err != nil {
		return [32]byte{}, rcpt, err
	}
	for _, lg := range rcpt.Logs {
		if len(lg.Topics) > 1 && lg.Topics[0] == m.Con.ABI.Events["KeyRegistered"].ID {
			return lg.Topics[1], rcpt, nil
		}
	}
	return [32]byte{}, rcpt, errors.New("chain: no KeyRegistered event")
}

// Order places an order and returns its ID.
func (m *Market) Order(from *Account, price *big.Int, offerID *big.Int, slot uint16, tRef uint64, comF, hInput, keyID [32]byte) (*big.Int, *types.Receipt, error) {
	rcpt, err := m.send(from, price, 0, "order", offerID, slot, tRef, comF, hInput, keyID)
	if err != nil {
		return nil, rcpt, err
	}
	id, err := m.eventUint(rcpt, "Ordered")
	return id, rcpt, err
}

// OrderRaw sends an order with an explicit gas limit (for expected reverts).
func (m *Market) OrderRaw(from *Account, value *big.Int, offerID *big.Int, slot uint16, tRef uint64, comF, hInput, keyID [32]byte) (*types.Receipt, error) {
	return m.send(from, value, 500_000, "order", offerID, slot, tRef, comF, hInput, keyID)
}

// ClaimDec sends the Case 2 claim.
func (m *Market) ClaimDec(from *Account, orderID, p *big.Int, proof []byte, gasLimit uint64) (*types.Receipt, error) {
	return m.send(from, nil, gasLimit, "claimDec", orderID, p, proof)
}

// BlobClaim mirrors FairExchangeMarket.BlobClaim.
type BlobClaim struct {
	HD         [32]byte
	YZ         *big.Int
	Commitment []byte
	KzgProof   []byte
}

// ClaimBlob sends the Case 1 claim as a type-3 transaction carrying sc.
func (m *Market) ClaimBlob(from *Account, orderID *big.Int, c BlobClaim, proof []byte, sc *types.BlobTxSidecar, gasLimit uint64) (*types.Receipt, error) {
	data, err := m.Con.ABI.Pack("claimBlob", orderID, c, proof)
	if err != nil {
		return nil, err
	}
	return m.Env.SendBlobTx(from, m.Addr, data, sc, gasLimit)
}

// CallClaimDec simulates the Case 2 claim against the latest block without
// sending it and returns the revert error, if any: a claim that reverts is
// still included, and its calldata publishes the partial decryption.
func (m *Market) CallClaimDec(from common.Address, orderID, p *big.Int, proof []byte, gasLimit uint64) error {
	data, err := m.Con.ABI.Pack("claimDec", orderID, p, proof)
	if err != nil {
		return err
	}
	_, err = m.Env.Client.CallContract(context.Background(), ethereum.CallMsg{From: from, To: &m.Addr, Gas: gasLimit, Data: data}, nil)
	return err
}

// CallClaimBlob simulates the Case 1 claim against the latest block with the
// versioned hashes of the sidecar's blobs, which BLOBHASH reads, and returns
// the revert error, if any: a claim that reverts is still included and
// publishes its blob.
func (m *Market) CallClaimBlob(from common.Address, orderID *big.Int, c BlobClaim, proof []byte, sc *types.BlobTxSidecar, gasLimit uint64) error {
	data, err := m.Con.ABI.Pack("claimBlob", orderID, c, proof)
	if err != nil {
		return err
	}
	_, err = m.Env.Client.CallContract(context.Background(), ethereum.CallMsg{From: from, To: &m.Addr, Gas: gasLimit, Data: data,
		BlobHashes: sc.BlobHashes()}, nil)
	return err
}

// ClaimBlobNoBlob sends the Case 1 claim without a blob (expected to revert).
func (m *Market) ClaimBlobNoBlob(from *Account, orderID *big.Int, c BlobClaim, proof []byte) (*types.Receipt, error) {
	return m.send(from, nil, 3_000_000, "claimBlob", orderID, c, proof)
}

// Refund, Reject and Retire.
func (m *Market) Refund(from *Account, orderID *big.Int, gasLimit uint64) (*types.Receipt, error) {
	return m.send(from, nil, gasLimit, "refund", orderID)
}

func (m *Market) Reject(from *Account, orderID *big.Int, gasLimit uint64) (*types.Receipt, error) {
	return m.send(from, nil, gasLimit, "reject", orderID)
}

func (m *Market) Retire(from *Account, offerID *big.Int, slot uint16, gasLimit uint64) (*types.Receipt, error) {
	return m.send(from, nil, gasLimit, "retire", offerID, slot)
}

// OrderState reads the state of an order (1 open, 2 claimed, 3 refunded,
// 4 rejected).
func (m *Market) OrderState(orderID *big.Int) (uint8, error) {
	out, err := m.call("orders", orderID)
	if err != nil {
		return 0, err
	}
	return out[len(out)-1].(uint8), nil
}

func (m *Market) call(method string, args ...interface{}) ([]interface{}, error) {
	data, err := m.Con.ABI.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	res, err := m.Env.Client.CallContract(context.Background(), callMsg(m.Addr, data), nil)
	if err != nil {
		return nil, err
	}
	return m.Con.ABI.Unpack(method, res)
}

// eventUint returns the first indexed uint256 topic of the named event.
func (m *Market) eventUint(rcpt *types.Receipt, name string) (*big.Int, error) {
	if rcpt.Status != types.ReceiptStatusSuccessful {
		return nil, fmt.Errorf("chain: %s transaction reverted", name)
	}
	id := m.Con.ABI.Events[name].ID
	for _, lg := range rcpt.Logs {
		if len(lg.Topics) > 1 && lg.Topics[0] == id {
			return new(big.Int).SetBytes(lg.Topics[1][:]), nil
		}
	}
	return nil, fmt.Errorf("chain: no %s event", name)
}

// Event decodes the non-indexed fields of the first event of the given name.
func (m *Market) Event(rcpt *types.Receipt, name string) (map[string]interface{}, error) {
	ev := m.Con.ABI.Events[name]
	for _, lg := range rcpt.Logs {
		if len(lg.Topics) > 0 && lg.Topics[0] == ev.ID {
			out := map[string]interface{}{}
			if err := ev.Inputs.NonIndexed().UnpackIntoMap(out, lg.Data); err != nil {
				return nil, err
			}
			return out, nil
		}
	}
	return nil, fmt.Errorf("chain: no %s event", name)
}

// SendBlobTx sends a type-3 transaction carrying the sidecar's blobs and
// mines it.
func (env *Env) SendBlobTx(from *Account, to common.Address, data []byte, sc *types.BlobTxSidecar, gasLimit uint64) (*types.Receipt, error) {
	ctx := context.Background()
	nonce, err := env.Client.PendingNonceAt(ctx, from.Addr)
	if err != nil {
		return nil, err
	}
	head, err := env.Client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, err
	}
	tip := big.NewInt(params.GWei)
	feeCap := new(big.Int).Add(new(big.Int).Mul(head.BaseFee, big.NewInt(2)), tip)
	if gasLimit == 0 {
		gasLimit = 3_000_000
	}
	tx := types.NewTx(&types.BlobTx{
		ChainID:    uint256.MustFromBig(env.ChainID),
		Nonce:      nonce,
		GasTipCap:  uint256.MustFromBig(tip),
		GasFeeCap:  uint256.MustFromBig(feeCap),
		Gas:        gasLimit,
		To:         to,
		Value:      new(uint256.Int),
		Data:       data,
		BlobFeeCap: uint256.NewInt(params.GWei), // the blob base fee of the dev chain is far lower
		BlobHashes: sc.BlobHashes(),
		Sidecar:    sc,
	})
	signed, err := types.SignTx(tx, env.signer, from.Key)
	if err != nil {
		return nil, err
	}
	if err := env.Client.SendTransaction(ctx, signed); err != nil {
		return nil, fmt.Errorf("chain: send blob tx: %w", err)
	}
	env.Backend.Commit()
	return env.Client.TransactionReceipt(ctx, signed.Hash())
}

// KZGBytes returns the 48-byte commitment and proof as byte slices.
func KZGBytes(c kzg4844.Commitment, p kzg4844.Proof) ([]byte, []byte) {
	return append([]byte{}, c[:]...), append([]byte{}, p[:]...)
}

// callMsg is a read-only call to addr.
func callMsg(addr common.Address, data []byte) ethereum.CallMsg {
	return ethereum.CallMsg{To: &addr, Data: data}
}

// OrderInfo is the stored state of an order.
type OrderInfo struct {
	OfferID      *big.Int
	Slot         uint16
	Buyer        common.Address
	Amount       *big.Int
	TOrder, TRef uint64
	ComF         [32]byte
	HInput       [32]byte
	HKey         [32]byte
	State        uint8
}

// OrderInfo reads an order.
func (m *Market) OrderInfo(orderID *big.Int) (*OrderInfo, error) {
	out, err := m.call("orders", orderID)
	if err != nil {
		return nil, err
	}
	return &OrderInfo{
		OfferID: out[0].(*big.Int), Slot: out[1].(uint16), Buyer: out[2].(common.Address),
		Amount: out[3].(*big.Int), TOrder: out[4].(uint64), TRef: out[5].(uint64),
		ComF: out[6].([32]byte), HInput: out[7].([32]byte), HKey: out[8].([32]byte), State: out[9].(uint8),
	}, nil
}

// OfferInfo is the stored state of an offer.
type OfferInfo struct {
	Seller, Payout          common.Address
	CaseId                  uint8
	ComX                    [32]byte
	Price                   *big.Int
	TMin, TMax              uint64
	Q                       uint16
	Terms                   [32]byte
	ClaimVk, KeyVk, InputVk [32]byte
}

// OfferInfo reads an offer.
func (m *Market) OfferInfo(offerID *big.Int) (*OfferInfo, error) {
	out, err := m.call("offer", offerID)
	if err != nil {
		return nil, err
	}
	o := out[0].(struct {
		Seller  common.Address `json:"seller"`
		Payout  common.Address `json:"payout"`
		CaseId  uint8          `json:"caseId"`
		ComX    [32]byte       `json:"comX"`
		Price   *big.Int       `json:"price"`
		TMin    uint64         `json:"tMin"`
		TMax    uint64         `json:"tMax"`
		Q       uint16         `json:"q"`
		Terms   [32]byte       `json:"terms"`
		ClaimVk [32]byte       `json:"claimVk"`
		KeyVk   [32]byte       `json:"keyVk"`
		InputVk [32]byte       `json:"inputVk"`
	})
	return &OfferInfo{Seller: o.Seller, Payout: o.Payout, CaseId: o.CaseId, ComX: o.ComX, Price: o.Price,
		TMin: o.TMin, TMax: o.TMax, Q: o.Q, Terms: o.Terms, ClaimVk: o.ClaimVk, KeyVk: o.KeyVk, InputVk: o.InputVk}, nil
}

// SlotInfo is the stored state of a slot.
type SlotInfo struct {
	State        uint8 // 0 free, 1 claimed, 2 retired
	OpenOrder    *big.Int
	HPk, HC1, HS [32]byte
}

// SlotInfo reads a slot.
func (m *Market) SlotInfo(offerID *big.Int, slot uint16) (*SlotInfo, error) {
	out, err := m.call("slotOf", offerID, slot)
	if err != nil {
		return nil, err
	}
	s := out[0].(struct {
		State     uint8    `json:"state"`
		OpenOrder *big.Int `json:"openOrder"`
		HPk       [32]byte `json:"hPk"`
		HC1       [32]byte `json:"hC1"`
		HS        [32]byte `json:"hS"`
	})
	return &SlotInfo{State: s.State, OpenOrder: s.OpenOrder, HPk: s.HPk, HC1: s.HC1, HS: s.HS}, nil
}

// BuyerKey reads a registered Case 1 key.
func (m *Market) BuyerKey(keyID [32]byte) (owner common.Address, keyIndex uint64, hPk, hSB [32]byte, err error) {
	out, err := m.call("buyerKeys", keyID)
	if err != nil {
		return
	}
	return out[0].(common.Address), out[1].(uint64), out[2].([32]byte), out[3].([32]byte), nil
}

// OrderKeyID returns the key ID recorded in the Ordered event of an order
// (Case 1).
func (m *Market) OrderKeyID(orderID *big.Int) ([32]byte, error) {
	ev, err := m.findEvent("Ordered", orderID)
	if err != nil {
		return [32]byte{}, err
	}
	return ev["keyId"].([32]byte), nil
}

// ClaimOf returns the decoded Claimed event of an order (p in Case 2, the
// blob's versionedHash and hD in Case 1), or nil if the order has no
// accepted claim yet.
func (m *Market) ClaimOf(orderID *big.Int) (map[string]interface{}, error) {
	ev, err := m.findEvent("Claimed", orderID)
	if err != nil {
		return nil, nil
	}
	return ev, nil
}

// ClaimEvent is an accepted claim as the ledger records it.
type ClaimEvent struct {
	OrderID *big.Int
	P       *big.Int // the Case 2 deliverable (0 in Case 1)
	VH, HD  [32]byte // the blob of the Case 1 deliverable (0 in Case 2)
	Block   uint64
}

// Claims returns the accepted claims of blocks from to to, in order.
func (m *Market) Claims(from, to uint64) ([]ClaimEvent, error) {
	ev := m.Con.ABI.Events["Claimed"]
	logs, err := m.Env.Client.FilterLogs(context.Background(), ethereum.FilterQuery{
		FromBlock: new(big.Int).SetUint64(from),
		ToBlock:   new(big.Int).SetUint64(to),
		Addresses: []common.Address{m.Addr},
		Topics:    [][]common.Hash{{ev.ID}},
	})
	if err != nil {
		return nil, err
	}
	out := make([]ClaimEvent, 0, len(logs))
	for _, lg := range logs {
		v, err := ev.Inputs.NonIndexed().Unpack(lg.Data)
		if err != nil {
			return nil, err
		}
		out = append(out, ClaimEvent{OrderID: new(big.Int).SetBytes(lg.Topics[1][:]), P: v[0].(*big.Int),
			VH: v[1].([32]byte), HD: v[2].([32]byte), Block: lg.BlockNumber})
	}
	return out, nil
}

// findEvent returns the non-indexed fields of the first event of the given
// name whose first indexed topic is id.
func (m *Market) findEvent(name string, id *big.Int) (map[string]interface{}, error) {
	ev := m.Con.ABI.Events[name]
	var topic common.Hash
	id.FillBytes(topic[:])
	logs, err := m.Env.Client.FilterLogs(context.Background(), ethereum.FilterQuery{
		Addresses: []common.Address{m.Addr},
		Topics:    [][]common.Hash{{ev.ID}, {topic}},
	})
	if err != nil {
		return nil, err
	}
	if len(logs) == 0 {
		return nil, fmt.Errorf("chain: no %s event for %s", name, id)
	}
	out := map[string]interface{}{}
	if err := ev.Inputs.NonIndexed().UnpackIntoMap(out, logs[0].Data); err != nil {
		return nil, err
	}
	return out, nil
}
