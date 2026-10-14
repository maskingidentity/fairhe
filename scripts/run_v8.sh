#!/usr/bin/env bash
# Reproduction harness of the implementation; mirrors
# scripts/run_v8.ps1. Usage: scripts/run_v8.sh [--quick]
set -euo pipefail
cd "$(dirname "$0")/.."
QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

echo "== 1/7 compile the market contract and the blob board (option O6) =="
python3 scripts/compile_sol.py contracts/FairExchangeMarket.sol contracts/out/FairExchangeMarket.json FairExchangeMarket
python3 scripts/compile_sol.py contracts/BlobBoard.sol contracts/out/BlobBoard.json BlobBoard
echo "== 2/7 tests =="
FAIRHE_RECORD=1 go test ./pkg/rlwe ./pkg/hashes ./pkg/valuation ./pkg/blob ./pkg/market ./pkg/zk/gadgets ./pkg/zk/valclass ./pkg/zk/keyproof ./pkg/zk/member ./pkg/zk/encproof ./pkg/zk/evalc2 ./pkg/zk/decproof ./pkg/zk/evalc1 ./pkg/zk/keys ./pkg/zk/registry ./pkg/zk/se ./pkg/zk/sealv8 -count=1 -timeout 60m
go test ./pkg/chain -run 'TestMarket|TestBlobBoard' -count=1 -timeout 30m
echo "== 3/7 parameter table and the margins of the actual chains (A6) =="
go run ./cmd/params
python3 scripts/check_margins_v8.py
echo "== 4/7 H_dig spike =="
FAIRHE_SPIKE=1 go test ./pkg/hashes -run TestHDigSpike -count=1 -timeout 60m
if [ "$QUICK" = 0 ]; then
  echo "== 5/7 full-scale proofs, one process per circuit and setting =="
  run() { FAIRHE_ZK_FULL=1 FAIRHE_ZK_PROVE=1 FAIRHE_ZK_REPS=5 FAIRHE_ZK_PARAMS="$3" GOGC=50 GOMEMLIMIT=28GiB go test "$1" -run "$2" -count=1 -timeout 4h; }
  for p in case1_bfv case1_ckks case2_bfv case2_ckks; do run ./pkg/zk/keyproof TestKeyProofFullScale "$p"; done
  for p in case1_bfv case1_ckks; do run ./pkg/zk/member TestMemberFullScale "$p"; run ./pkg/zk/member TestO2SEFullScale "$p"; run ./pkg/zk/evalc1 TestEvalC1FullScale "$p"; done
  for p in case2_bfv case2_ckks; do
    run ./pkg/zk/encproof TestEncProofFullScale "$p"
    run ./pkg/zk/evalc2 TestEvalC2FullScale "$p"
    run ./pkg/zk/decproof TestDecProofFullScale "$p"
  done
  # option O1: pi_seal and the sealed correctness proofs
  for p in case1_bfv case1_ckks case2_bfv; do run ./pkg/zk/sealv8 TestSealFullScale "$p"; done
  for p in case2_bfv case2_ckks; do run ./pkg/zk/decproof TestSealedDecProofFullScale "$p"; done
  for p in case1_bfv case1_ckks; do run ./pkg/zk/evalc1 TestSealedEvalC1FullScale "$p"; done
  echo "== 6/7 full-scale keys and end-to-end scenarios =="
  GOGC=50 GOMEMLIMIT=28GiB go run ./cmd/keys -scale full
  GOGC=50 GOMEMLIMIT=28GiB go run ./cmd/e2e -scale full -scenarios happy,reject,refund,late -reps 5
  GOGC=50 GOMEMLIMIT=28GiB go run ./cmd/e2e -scale full -board blob -scenarios happy -reps 5 # option O6
  GOGC=50 GOMEMLIMIT=28GiB go run ./cmd/e2e -scale full -params case1_bfv,case1_ckks -scenarios archive -reps 5 # option O7
else
  echo "== 6/7 end-to-end scenarios at reduced size =="
  go run ./cmd/e2e -scale small
fi
echo "== 7/7 LaTeX fragments =="
python3 scripts/gen_v8_tables.py
echo "done: results/v8/*.jsonl and results/v8/tex/*.tex"
echo "test G1 (lattice estimator): bash scripts/setup_wsl_sage.sh, then python of the sage env: scripts/security_v8.py (README)"
