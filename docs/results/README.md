# Measurement snapshot

A copy of `results/v8/` (which the scripts regenerate and git does not
track) taken after the full-scale runs that the paper reports. Times are
medians of 5 runs; accuracy is taken over 1,000 inputs per parameter set.
The JSONL files keep every measured row; the tables use the latest runs.
Table numbers refer to the full version of the paper.

| File | Content | Produced by |
|---|---|---|
| `params.jsonl`, `tab_v8_params.tex` | Table 3: N, chains, t or Delta, q_del, flood widths, margins, deliverable and blob elements, accuracy, pre-flood noise, security | `go run ./cmd/params`, `accuracy.jsonl` |
| `accuracy.jsonl` | Tests A1-A5: 1,000 inputs per set, largest CKKS error, largest pre-flood noise against its bound | `FAIRHE_RECORD=1 go test ./pkg/rlwe -run 'TestA1A2A5Case1\|TestA3A4A5Case2'` |
| `zk.jsonl`, `tab_v8_zk.tex` | Table 5: constraints, public inputs, setup, prove and verify (medians of 5), proof size, peak commit | full-scale ZK tests with `FAIRHE_ZK_REPS=5`, one process per circuit and setting |
| `e2e.jsonl`, `tab_v8_costs.tex`, `tab_v8_gas.tex` | Table 4: per-role times (medians of 5 exchanges), communication including ledger calldata and blobs, settlement gas | `go run ./cmd/e2e -scale full -reps 5` |
| `se.jsonl`, `tab_v8_se.tex` | Option O2: cost of the straight-line-extraction gadget per encrypted element, pi_member with and without it (measured), estimates for the other proofs | `FAIRHE_RECORD=1 go test ./pkg/zk/se -run TestCostModel`, `TestO2SEFullScale` |
| `tab_v8_o1.tex` | Option O1: pi_seal and the sealed correctness proofs at full scale | `TestSealFullScale`, `TestSealedEvalC1FullScale`, `TestSealedDecProofFullScale` with `FAIRHE_ZK_REPS=5` |
| `e2e.jsonl` (rows with `"board": "blob"`), `tab_v8_o6.tex` | Option O6: the bulky values as blob data (payloads and blobs per message, blobs and gas per exchange, posting time, the same payloads as calldata) | `go run ./cmd/e2e -scale full -board blob -scenarios happy -reps 5` |
| `archive.jsonl`, `e2e.jsonl` (scenario `archive`), `tab_v8_o7.tex` | Option O7: the archive of the claim blobs (storage, store and read-back costs per claim, exchanges decoded from it after W) | `FAIRHE_RECORD=1 go test ./pkg/market -run TestO7ArchiveCost`, `go run ./cmd/e2e -scale full -params case1_bfv,case1_ckks -scenarios archive -reps 5` |
| `security.jsonl` | Test G1: lattice estimator (commit 53da598) on the actual chains and at q = 2^logQ | `scripts/security_v8.py` under SageMath |
| `hdig_spike.jsonl` | Cost of H_dig candidates in-circuit: MiMC, Poseidon2, GKR-Poseidon2 | `FAIRHE_SPIKE=1 go test ./pkg/hashes -run TestHDigSpike` |
| `manifest_full.json` | The 14 full-scale verification keys: VK IDs, constants, setup times | `go run ./cmd/keys -scale full` |

Machine: Windows 10, 32 GB RAM (commit limit 37.6 GiB), Go 1.25.7,
gnark v0.15.0, Lattigo v6.1.1, go-ethereum v1.17.4 simulated backend.
Full-scale proofs ran with `GOGC=50 GOMEMLIMIT=28GiB`. Reproduce everything
with `scripts/run_v8.sh` (or `scripts/run_v8.ps1`), then
`python scripts/gen_v8_tables.py`; test G1 runs under SageMath
(`scripts/setup_wsl_sage.sh`, then the Sage environment's
`python scripts/security_v8.py`).
