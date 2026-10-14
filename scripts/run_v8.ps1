# Reproduction harness of the implementation.
#   powershell -ExecutionPolicy Bypass -File scripts\run_v8.ps1 [-Quick]
# Regenerates results/v8/*.jsonl and the LaTeX fragments in results/v8/tex.
# Requires Go >= 1.25 and Python 3 with py-solc-x. Full-scale proofs need
# about 11 GiB of commit (Case 1 pi_eval); -Quick skips the full-scale steps.
# Times are medians of 5 runs (proofs: FAIRHE_ZK_REPS; exchanges: -reps).
# Keys are set up locally (not a ceremony) under keys/full.
param([switch]$Quick)

$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

function Step($msg, [scriptblock]$cmd) {
    Write-Host "== $msg =="
    & $cmd
    if ($LASTEXITCODE -ne 0) { throw "$msg failed" }
}

Step '1/7 compile the market contract and the blob board (option O6)' {
    python scripts\compile_sol.py contracts\FairExchangeMarket.sol contracts\out\FairExchangeMarket.json FairExchangeMarket
    if ($LASTEXITCODE -ne 0) { return }
    python scripts\compile_sol.py contracts\BlobBoard.sol contracts\out\BlobBoard.json BlobBoard
}
Step '2/7 v8 tests (HE layer with 1,000 inputs per set, gadgets, proofs at reduced size, contract, state machines)' {
    $env:FAIRHE_RECORD = '1' # A1-A5 maxima to results/v8/accuracy.jsonl
    go test ./pkg/rlwe ./pkg/hashes ./pkg/valuation ./pkg/blob ./pkg/market ./pkg/zk/gadgets ./pkg/zk/valclass ./pkg/zk/keyproof ./pkg/zk/member ./pkg/zk/encproof ./pkg/zk/evalc2 ./pkg/zk/decproof ./pkg/zk/evalc1 ./pkg/zk/keys ./pkg/zk/registry ./pkg/zk/se ./pkg/zk/sealv8 -count=1 -timeout 60m
    Remove-Item Env:FAIRHE_RECORD
    if ($LASTEXITCODE -ne 0) { return }
    go test ./pkg/chain -run 'TestMarket|TestBlobBoard' -count=1 -timeout 30m
}
Step '3/7 parameter table and the margins of the actual chains (A6)' {
    go run ./cmd/params
    if ($LASTEXITCODE -ne 0) { return }
    python scripts\check_margins_v8.py
}
Step '4/7 H_dig spike (MiMC vs Poseidon2)' {
    $env:FAIRHE_SPIKE = '1'; go test ./pkg/hashes -run TestHDigSpike -count=1 -timeout 60m; Remove-Item Env:FAIRHE_SPIKE
}
if (-not $Quick) {
    Step '5/7 full-scale proofs, one process per circuit and setting' {
        $env:FAIRHE_ZK_FULL = '1'; $env:FAIRHE_ZK_PROVE = '1'; $env:FAIRHE_ZK_REPS = '5'; $env:GOGC = '50'; $env:GOMEMLIMIT = '28GiB'
        $runs = @(
            @('./pkg/zk/keyproof', 'TestKeyProofFullScale', @('case1_bfv', 'case1_ckks', 'case2_bfv', 'case2_ckks')),
            @('./pkg/zk/member', 'TestMemberFullScale', @('case1_bfv', 'case1_ckks')),
            @('./pkg/zk/member', 'TestO2SEFullScale', @('case1_bfv', 'case1_ckks')),
            @('./pkg/zk/encproof', 'TestEncProofFullScale', @('case2_bfv', 'case2_ckks')),
            @('./pkg/zk/evalc2', 'TestEvalC2FullScale', @('case2_bfv', 'case2_ckks')),
            @('./pkg/zk/decproof', 'TestDecProofFullScale', @('case2_bfv', 'case2_ckks')),
            @('./pkg/zk/evalc1', 'TestEvalC1FullScale', @('case1_bfv', 'case1_ckks')),
            # option O1: pi_seal and the sealed correctness proofs
            @('./pkg/zk/sealv8', 'TestSealFullScale', @('case1_bfv', 'case1_ckks', 'case2_bfv')),
            @('./pkg/zk/decproof', 'TestSealedDecProofFullScale', @('case2_bfv', 'case2_ckks')),
            @('./pkg/zk/evalc1', 'TestSealedEvalC1FullScale', @('case1_bfv', 'case1_ckks'))
        )
        foreach ($r in $runs) {
            foreach ($p in $r[2]) {
                $env:FAIRHE_ZK_PARAMS = $p
                go test $r[0] -run $r[1] -count=1 -timeout 4h
                if ($LASTEXITCODE -ne 0) { throw "$($r[1]) $p failed" }
            }
        }
        foreach ($v in 'FAIRHE_ZK_FULL', 'FAIRHE_ZK_PROVE', 'FAIRHE_ZK_REPS', 'FAIRHE_ZK_PARAMS', 'GOGC', 'GOMEMLIMIT') { Remove-Item "Env:$v" }
    }
    Step '6/7 full-scale keys and end-to-end scenarios' {
        $env:GOGC = '50'; $env:GOMEMLIMIT = '28GiB'
        go run ./cmd/keys -scale full
        if ($LASTEXITCODE -ne 0) { throw 'key setup failed' }
        go run ./cmd/e2e -scale full -scenarios happy,reject,refund,late -reps 5
        if ($LASTEXITCODE -ne 0) { throw 'end-to-end scenarios failed' }
        go run ./cmd/e2e -scale full -board blob -scenarios happy -reps 5 # option O6
        go run ./cmd/e2e -scale full -params case1_bfv,case1_ckks -scenarios archive -reps 5 # option O7
        Remove-Item Env:GOGC; Remove-Item Env:GOMEMLIMIT
    }
} else {
    Step '6/7 end-to-end scenarios at reduced size' { go run ./cmd/e2e -scale small }
}
Step '7/7 LaTeX fragments' { python scripts\gen_v8_tables.py }
Write-Host 'done: results/v8/*.jsonl and results/v8/tex/*.tex'
Write-Host 'test G1 (lattice estimator) runs under SageMath in WSL: scripts/setup_wsl_sage.sh, then scripts/security_v8.py (README)'
