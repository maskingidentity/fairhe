# fairhe

Implementation and measurements for the paper *Privacy-Preserving Fair
Exchange of Computation via Homomorphic Encryption and Proof-Carrying
Claims*. A seller holds data, a buyer holds a function from a public class,
and the buyer obtains the result if and only if the seller is paid, while
neither learns the other's input:

- **Case 1** (encrypted function): the buyer encrypts its function; the
  seller evaluates it on its plaintext data, sanitises the result against
  the key holder, extracts the output coefficient and switches it to a small
  modulus.
- **Case 2** (encrypted data): the seller encrypts its data; the buyer
  evaluates its function, keeps the first ciphertext component, and the
  seller returns a flooded partial decryption of the second.
- **Settlement**: the seller's claim carries the deliverable (as EIP-4844
  blob data in Case 1) with a zero-knowledge proof that it is correct, and
  the contract pays only if the proof verifies.

The running example is a pre-purchase valuation of a dataset: the squared
error of the buyer's linear model on the seller's records, computed from the
sufficient statistics of the records. Four parameter sets are implemented:
Case 1 and Case 2, each with BFV and CKKS, at N = 2^13.

Section, table and equation numbers in comments and docs refer to the full
version of the paper. File names with `v8` (for example `scripts/run_v8.sh`
and `results/v8/`) carry the internal version label of the protocol that the
paper describes.

## Layout

| Path | Content |
|---|---|
| `pkg/rlwe` | Textbook BFV and coefficient-encoded CKKS on Lattigo's ring package: the four parameter sets of Table 2 with exact margin checks, public-coin keys, secret-key encryption, the Case 1 sanitisation, extraction and modulus switch, the Case 2 slots and partial decryption, and plain-Go checkers of every proven relation |
| `pkg/hashes` | Domain-separated hashes: H_coin (public coins), H_dig (Poseidon2 on BN254 and BLS12-381), H_pt (blob evaluation point), salted commitments |
| `pkg/valuation` | The running example: data generator, statistics, expanded weights, encodings, class bounds |
| `pkg/zk/gadgets` | Circuit building blocks: exact range checks, polynomial identities over Z[X] checked at a committed random point, digests, the barycentric blob evaluation |
| `pkg/zk/keyproof`, `member`, `encproof`, `evalc1`, `evalc2`, `decproof` | The proofs pi_key, pi_member, pi_enc, Case 1 pi_eval, Case 2 pi_eval and pi_dec (Groth16, gnark) |
| `pkg/zk/registry`, `pkg/zk/keys`, `cmd/keys` | Circuit registry, local Groth16 setup, verification-key IDs, Solidity verifiers, deployment manifest |
| `pkg/zk/valclass`, `pkg/zk/zkmeasure` | The function class inside the circuits; the proof measurement harness |
| `pkg/zk/se`, `pkg/zk/member/se.go` | Option O2: straight-line extraction by encrypting the witness inside the circuit |
| `pkg/zk/sealv8`, `pkg/zk/evalc1/sealed.go`, `pkg/zk/decproof/sealed.go`, `pkg/adaptor` | Option O1: the sealing proof, the sealed correctness proofs and the adaptor signatures of the settlement for chains that cannot verify proofs |
| `contracts/FairExchangeMarket.sol`, `contracts/BlobBoard.sol` | Settlement contract (registration, orders, proof-carrying claims, blob link, refund, reject, retire) and the blob board of option O6 |
| `pkg/chain`, `pkg/onchain` | Drivers of the contracts on the go-ethereum simulated backend; export and compilation of the Solidity verifiers |
| `pkg/blob` | The Case 1 deliverable as an EIP-4844 blob (packing, KZG commitment and opening, evaluation point, sidecar) |
| `pkg/market` | The seller's and buyer's state machines, the boards of the bulky values (a data-availability layer or blob data), the blob retention stand-in and the archive of option O7 |
| `pkg/clock` | High-resolution timer for the measurements |
| `cmd/params`, `cmd/e2e` | The parameter table, and end-to-end exchanges on the simulated chain |
| `scripts/` | Contract compilation, reproduction harnesses, LaTeX tables, margin check, lattice estimator |
| `docs/tests.md`, `docs/limitations.md` | Test IDs mapped to the tests; assumptions and limitations of the prototype |
| `docs/results/` | Snapshot of the measurements and tables that the paper reports |

## Requirements

- Go 1.25 (see `go.mod`).
- Python 3 with `py-solc-x` (`pip install py-solc-x`) for the contracts;
  solc 0.8.24 is downloaded on first use.
- Full-scale proofs: about 11 GiB of memory for the Case 1 claim proof (the
  measurements ran on a 32 GB machine); the full-scale proving keys take
  several GiB under `keys/`.
- Lattice estimator (test G1): SageMath and the lattice estimator, installed
  by `scripts/setup_wsl_sage.sh` (Linux or WSL).

## Quick start

```bash
go build ./...
go test -short ./...                 # reduced-size proofs, no Python needed
python scripts/compile_sol.py contracts/FairExchangeMarket.sol contracts/out/FairExchangeMarket.json FairExchangeMarket
python scripts/compile_sol.py contracts/BlobBoard.sol contracts/out/BlobBoard.json BlobBoard
go test ./pkg/chain ./pkg/market     # contract and state-machine tests
go run ./cmd/params                  # parameter table -> results/v8/params.jsonl
go run ./cmd/e2e -scale small        # end-to-end exchanges with reduced-size proofs
```

## Reproducing the measurements

```bash
bash scripts/run_v8.sh               # or: powershell -ExecutionPolicy Bypass -File scripts/run_v8.ps1
bash scripts/run_v8.sh --quick       # skips the full-scale proofs and keys
python scripts/gen_v8_tables.py      # LaTeX tables -> results/v8/tex/
```

The harness compiles the contracts, runs the tests, writes the parameter
table, measures every proof at full scale (one process per circuit and
setting, medians of 5), sets up the full-scale keys and runs the end-to-end
scenarios. Results go to `results/v8/*.jsonl`; `docs/results/` holds the
snapshot that the paper reports.

For test G1:

```bash
bash scripts/setup_wsl_sage.sh
$HOME/fairhe-sage/miniforge/envs/sage/bin/python scripts/security_v8.py --le $HOME/fairhe-sage/lattice-estimator
```

## Options

Optional parts of the implementation carry these labels in test names,
scripts and tables; O1, O2, O6 and O7 are the variants measured in
Section 6.4.

| Label | Variant |
|---|---|
| O1 | Settlement for chains that cannot verify proofs (Appendix B): the sealing proof and the sealed correctness proofs, measured at full scale; the adaptor-signature settlement itself is not run end to end |
| O2 | Straight-line extraction of pi_member's witness by in-circuit encryption |
| O5 | Public-coin components kept out of the data-availability layer: the counterparty recomputes them |
| O6 | The bulky values (keys, ciphertexts, off-chain proofs) posted as blob data instead of a data-availability layer |
| O7 | An archive of the claim blobs that serves the deliverable after the retention window |

## Limitations

The Groth16 proofs are not simulation-extractable (option O2 adds
straight-line extraction to pi_member only), the setup is local rather than
a ceremony, the ledger is a single simulated node, and the data-availability
layer is a local store. See `docs/limitations.md`.
