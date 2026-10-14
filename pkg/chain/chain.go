// Package chain runs the settlement on the go-ethereum simulated backend
// (ethclient/simulated): the same EVM and gas accounting as a live node, with
// block production under test control. This file holds the common pieces
// (accounts, the simulated chain, transaction sending and contract artifacts);
// market.go drives the settlement contract FairExchangeMarket.sol and board.go
// the blob board BlobBoard.sol.
//
// Contract artifacts are the ABI+bytecode JSON files that
// scripts/compile_sol.py writes to contracts/out/; they are loaded at runtime
// through the go-ethereum abi package (no abigen step).
package chain

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"
	"github.com/ethereum/go-ethereum/params"
)

// Contract is a compiled contract artifact: parsed ABI plus creation bytecode.
type Contract struct {
	Name string
	ABI  abi.ABI
	Bin  []byte
}

// LoadContract parses one contracts/out/*.json artifact produced by
// scripts/compile_sol.py ({"contractName", "abi", "bin", ...}).
func LoadContract(path string) (*Contract, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("chain: read artifact: %w", err)
	}
	var cj struct {
		Name string          `json:"contractName"`
		ABI  json.RawMessage `json:"abi"`
		Bin  string          `json:"bin"`
	}
	if err := json.Unmarshal(raw, &cj); err != nil {
		return nil, fmt.Errorf("chain: parse artifact %s: %w", path, err)
	}
	parsed, err := abi.JSON(strings.NewReader(string(cj.ABI)))
	if err != nil {
		return nil, fmt.Errorf("chain: parse ABI of %s: %w", path, err)
	}
	bin, err := hex.DecodeString(strings.TrimPrefix(cj.Bin, "0x"))
	if err != nil {
		return nil, fmt.Errorf("chain: decode bytecode of %s: %w", path, err)
	}
	if len(bin) == 0 {
		return nil, fmt.Errorf("chain: empty creation bytecode in %s", path)
	}
	return &Contract{Name: cj.Name, ABI: parsed, Bin: bin}, nil
}

// Account is an EOA on the simulated chain (seller or buyer).
type Account struct {
	Key  *ecdsa.PrivateKey
	Addr common.Address
}

// NewAccount generates a fresh EOA key pair.
func NewAccount() (*Account, error) {
	key, err := crypto.GenerateKey()
	if err != nil {
		return nil, err
	}
	return &Account{Key: key, Addr: crypto.PubkeyToAddress(key.PublicKey)}, nil
}

// Env is a running simulated chain plus its RPC client.
type Env struct {
	Backend *simulated.Backend
	Client  simulated.Client
	ChainID *big.Int
	signer  types.Signer
}

// NewEnv starts a simulated backend with each given account pre-funded with
// 1000 ETH. The simulated backend always runs chain ID 1337 on the full
// dev-chain fork schedule (through Prague/Osaka, so EIP-7623 calldata floor
// pricing is active).
func NewEnv(funded ...*Account) (*Env, error) {
	alloc := types.GenesisAlloc{}
	bal := new(big.Int).Mul(big.NewInt(1000), big.NewInt(params.Ether))
	for _, a := range funded {
		alloc[a.Addr] = types.Account{Balance: new(big.Int).Set(bal)}
	}
	backend := simulated.NewBackend(alloc)
	client := backend.Client()
	chainID, err := client.ChainID(context.Background())
	if err != nil {
		backend.Close()
		return nil, fmt.Errorf("chain: query chain ID: %w", err)
	}
	return &Env{
		Backend: backend,
		Client:  client,
		ChainID: chainID,
		signer:  types.LatestSignerForChainID(chainID),
	}, nil
}

// Close shuts the backend down.
func (env *Env) Close() error { return env.Backend.Close() }

// SendTx builds, signs, sends and mines a single EIP-1559 transaction and
// returns its receipt (to == nil deploys a contract). gasLimit == 0 means
// "estimate first"; estimation surfaces the node's revert error, so tests
// that EXPECT a revert pass an explicit limit to get a mined receipt with
// Status == 0 instead.
func (env *Env) SendTx(from *Account, to *common.Address, value *big.Int, data []byte, gasLimit uint64) (*types.Receipt, error) {
	ctx := context.Background()
	if value == nil {
		value = new(big.Int)
	}
	nonce, err := env.Client.PendingNonceAt(ctx, from.Addr)
	if err != nil {
		return nil, fmt.Errorf("chain: nonce: %w", err)
	}
	head, err := env.Client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("chain: head: %w", err)
	}
	tip := big.NewInt(params.GWei)
	feeCap := new(big.Int).Add(new(big.Int).Mul(head.BaseFee, big.NewInt(2)), tip)
	if gasLimit == 0 {
		est, err := env.Client.EstimateGas(ctx, ethereum.CallMsg{
			From: from.Addr, To: to, Value: value, Data: data,
			GasFeeCap: feeCap, GasTipCap: tip,
		})
		if err != nil {
			return nil, fmt.Errorf("chain: estimate gas: %w", err)
		}
		// Headroom on the limit only; receipt.GasUsed is unaffected.
		gasLimit = est + est/10
	}
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID: env.ChainID, Nonce: nonce,
		GasTipCap: tip, GasFeeCap: feeCap, Gas: gasLimit,
		To: to, Value: value, Data: data,
	})
	signed, err := types.SignTx(tx, env.signer, from.Key)
	if err != nil {
		return nil, fmt.Errorf("chain: sign tx: %w", err)
	}
	if err := env.Client.SendTransaction(ctx, signed); err != nil {
		return nil, fmt.Errorf("chain: send tx: %w", err)
	}
	env.Backend.Commit()
	rcpt, err := env.Client.TransactionReceipt(ctx, signed.Hash())
	if err != nil {
		return nil, fmt.Errorf("chain: receipt: %w", err)
	}
	return rcpt, nil
}

// TxSpec is one transaction of SendInOneBlock.
type TxSpec struct {
	From     *Account
	To       *common.Address
	Value    *big.Int
	Data     []byte
	GasLimit uint64 // required: nothing is estimated against a pending block
	TipGwei  int64  // priority fee; a higher tip is included first (default 1)
}

// SendInOneBlock signs and sends the transactions and mines them in a single
// block, returning their receipts in the order given (tests of rules that
// depend on two transactions sharing a block number).
func (env *Env) SendInOneBlock(specs []TxSpec) ([]*types.Receipt, error) {
	ctx := context.Background()
	head, err := env.Client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("chain: head: %w", err)
	}
	nonces := map[common.Address]uint64{}
	var hashes []common.Hash
	for _, s := range specs {
		n, seen := nonces[s.From.Addr]
		if !seen {
			if n, err = env.Client.NonceAt(ctx, s.From.Addr, nil); err != nil {
				return nil, fmt.Errorf("chain: nonce: %w", err)
			}
		}
		nonces[s.From.Addr] = n + 1
		tipGwei := s.TipGwei
		if tipGwei == 0 {
			tipGwei = 1
		}
		tip := new(big.Int).Mul(big.NewInt(tipGwei), big.NewInt(params.GWei))
		value := s.Value
		if value == nil {
			value = new(big.Int)
		}
		tx := types.NewTx(&types.DynamicFeeTx{
			ChainID: env.ChainID, Nonce: n,
			GasTipCap: tip, GasFeeCap: new(big.Int).Add(new(big.Int).Mul(head.BaseFee, big.NewInt(2)), tip),
			Gas: s.GasLimit, To: s.To, Value: value, Data: s.Data,
		})
		signed, err := types.SignTx(tx, env.signer, s.From.Key)
		if err != nil {
			return nil, fmt.Errorf("chain: sign tx: %w", err)
		}
		if err := env.Client.SendTransaction(ctx, signed); err != nil {
			return nil, fmt.Errorf("chain: send tx: %w", err)
		}
		hashes = append(hashes, signed.Hash())
	}
	env.Backend.Commit()
	out := make([]*types.Receipt, len(hashes))
	for i, h := range hashes {
		if out[i], err = env.Client.TransactionReceipt(ctx, h); err != nil {
			return nil, fmt.Errorf("chain: receipt: %w", err)
		}
	}
	return out, nil
}

// BalanceAt returns the current balance of addr.
func (env *Env) BalanceAt(addr common.Address) (*big.Int, error) {
	return env.Client.BalanceAt(context.Background(), addr, nil)
}

// GasCost is the wei actually paid for the transaction of rcpt.
func GasCost(rcpt *types.Receipt) *big.Int {
	return new(big.Int).Mul(new(big.Int).SetUint64(rcpt.GasUsed), rcpt.EffectiveGasPrice)
}
