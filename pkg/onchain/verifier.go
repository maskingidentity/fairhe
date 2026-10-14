// Package onchain runs the on-chain proofs through their Solidity
// verifiers: it exports a gnark Groth16 verifying key (BN254 for pi_dec,
// BLS12-381 with the EIP-2537 precompiles for the Case 1 pi_eval), compiles
// it with scripts/compile_sol.py (solc 0.8.24, evmVersion cancun), deploys
// it on the go-ethereum simulated backend and sends verifyProof(proof,
// input) as a transaction. Proofs for these verifiers are made with gnark's
// Solidity target (keccak256 hash-to-field for the commitment challenge).
package onchain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"

	"fairhe/pkg/chain"

	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bnfr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/backend/witness"
	"github.com/ethereum/go-ethereum/core/types"
)

// ProverOption is the option of groth16.Prove for proofs that a Solidity
// verifier checks.
func ProverOption() backend.ProverOption {
	return solidity.WithProverTargetSolidityVerifier(backend.GROTH16)
}

// VerifierOption is the matching option of groth16.Verify.
func VerifierOption() backend.VerifierOption {
	return solidity.WithVerifierTargetSolidityVerifier(backend.GROTH16)
}

// RepoRoot returns the directory of go.mod above the working directory.
func RepoRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for d := wd; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d, nil
		}
		if filepath.Dir(d) == d {
			return "", fmt.Errorf("onchain: no go.mod above %s", wd)
		}
	}
}

// CompileVerifier exports vk to contracts/v8/<name>.g.sol, compiles it to
// contracts/out/<name>.json and loads the artifact. Groth16 setup is
// randomised, so every new key needs this step before an on-chain check.
func CompileVerifier(vk groth16.VerifyingKey, name string) (*chain.Contract, error) {
	root, err := RepoRoot()
	if err != nil {
		return nil, err
	}
	var src bytes.Buffer
	if err := vk.ExportSolidity(&src); err != nil {
		return nil, fmt.Errorf("onchain: export: %w", err)
	}
	solPath := filepath.Join(root, "contracts", "v8", name+".g.sol")
	outPath := filepath.Join(root, "contracts", "out", name+".json")
	if err := os.MkdirAll(filepath.Dir(solPath), 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(solPath, src.Bytes(), 0o644); err != nil {
		return nil, err
	}
	if err := runSolc(root, solPath, outPath, "Verifier"); err != nil {
		return nil, err
	}
	return chain.LoadContract(outPath)
}

// runSolc invokes scripts/compile_sol.py with the first python on PATH.
func runSolc(root, src, out, contract string) error {
	var py string
	for _, cand := range []string{"python", "python3", "py"} {
		if p, err := exec.LookPath(cand); err == nil {
			py = p
			break
		}
	}
	if py == "" {
		return errors.New("onchain: no python interpreter on PATH (needed for scripts/compile_sol.py)")
	}
	cmd := exec.Command(py, filepath.Join(root, "scripts", "compile_sol.py"), src, out, contract)
	cmd.Dir = root
	if msg, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("onchain: solc: %v\n%s", err, msg)
	}
	return nil
}

// Result is one on-chain verification.
type Result struct {
	DeployGas  uint64
	VerifyGas  uint64
	OK         bool
	ProofBytes int
}

// ProofBytes returns the Solidity encoding of a Groth16 proof.
func ProofBytes(proof groth16.Proof) ([]byte, error) {
	m, ok := proof.(interface{ MarshalSolidity() []byte })
	if !ok {
		return nil, errors.New("onchain: proof has no Solidity encoding")
	}
	return m.MarshalSolidity(), nil
}

// PublicInputs returns the public witness as integers.
func PublicInputs(pub witness.Witness) ([]*big.Int, error) {
	switch v := pub.Vector().(type) {
	case bnfr.Vector:
		out := make([]*big.Int, len(v))
		for i := range v {
			out[i] = v[i].BigInt(new(big.Int))
		}
		return out, nil
	case blsfr.Vector:
		out := make([]*big.Int, len(v))
		for i := range v {
			out[i] = v[i].BigInt(new(big.Int))
		}
		return out, nil
	}
	return nil, errors.New("onchain: unsupported witness field")
}

// VerifyOnChain deploys the verifier on a fresh simulated chain and sends
// verifyProof(proof, input) as a transaction with an explicit gas limit, so
// that a failing proof yields a mined receipt with status 0.
func VerifyOnChain(con *chain.Contract, proof []byte, input []*big.Int) (*Result, error) {
	caller, err := chain.NewAccount()
	if err != nil {
		return nil, err
	}
	env, err := chain.NewEnv(caller)
	if err != nil {
		return nil, err
	}
	defer env.Close()
	dep, err := env.SendTx(caller, nil, nil, con.Bin, 0)
	if err != nil {
		return nil, fmt.Errorf("onchain: deploy: %w", err)
	}
	if dep.Status != types.ReceiptStatusSuccessful {
		return nil, errors.New("onchain: deploy reverted")
	}
	if code, err := env.Client.CodeAt(context.Background(), dep.ContractAddress, nil); err != nil || len(code) == 0 {
		return nil, fmt.Errorf("onchain: no code at the verifier address (%v)", err)
	}
	arr := reflect.New(reflect.ArrayOf(len(input), reflect.TypeOf(&big.Int{}))).Elem()
	for i, x := range input {
		arr.Index(i).Set(reflect.ValueOf(x))
	}
	data, err := con.ABI.Pack("verifyProof", proof, arr.Interface())
	if err != nil {
		return nil, fmt.Errorf("onchain: pack: %w", err)
	}
	addr := dep.ContractAddress
	rcpt, err := env.SendTx(caller, &addr, nil, data, 3_000_000)
	if err != nil {
		return nil, err
	}
	return &Result{DeployGas: dep.GasUsed, VerifyGas: rcpt.GasUsed, OK: rcpt.Status == types.ReceiptStatusSuccessful, ProofBytes: len(proof)}, nil
}
