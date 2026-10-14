# Tests

The tests are grouped by letter: A (accuracy and margins of the HE layer),
B (boundaries of each proof), C (the attacks that the proofs refuse), D (the
rules of the settlement contract), E (the seller's and buyer's state
machines), F (the blob link of the Case 1 deliverable) and G (security
estimate and measurements). Test names and comments use the same IDs.
Reduced-size proofs use N = 2^6 with the primes, moduli, flood widths and
bounds of the full parameter sets; full-scale runs are opt-in
(`FAIRHE_ZK_FULL=1`, `cmd/e2e -scale full`). Run everything with
`scripts/run_v8.sh` (or `scripts/run_v8.ps1`).

| Test | What is checked | Where |
|---|---|---|
| A1 | Case 1 BFV: 1,000 inputs including the worst case decode exactly | `pkg/rlwe` `TestA1A2A5Case1` |
| A2 | Case 1 CKKS: 1,000 inputs, error <= tau = 2^-10.41 | `pkg/rlwe` `TestA1A2A5Case1` |
| A3 | Case 2 BFV: exact | `pkg/rlwe` `TestA3A4A5Case2` (1,000 inputs) |
| A4 | Case 2 CKKS: error <= tau ~ 2^-10 | `pkg/rlwe` `TestA3A4A5Case2` (1,000 inputs) |
| A5 | Noise before the flood below B_tot, B_e | both tests above: measured on c_san (Case 1) and on c2 (Case 2, against B_e + B_err, the buyer's e0' included) |
| A6 | Actual Q and q_del keep the margins of C.4, by script | `pkg/rlwe` `TestA6Margins`; `scripts/check_margins_v8.py` (independent, exact, from `params.jsonl`) |
| B1 | pi_key: e_pk = 20, a secret coefficient 2, h_s mismatch; a not on the public coin refused by the verifier | `pkg/zk/keyproof` `TestKeyProofSmall`, `TestB1KeyProofBoundaries`; `pkg/market` `TestB1BuyerKeyNotOnPublicCoin` (seller), `TestC3SlotNotOnPublicCoin` (buyer) |
| B2 | pi_member: w > w_max, w_hat not the expansion of w, e_c = 20, another s (h_sB), Com(f) of other w | `pkg/zk/member` `TestMemberSmall`, `TestB2MemberBoundaries` |
| B3 | pi_enc: e_c1 = 20, data out of range, Com(x) of other S, another s | `pkg/zk/encproof` `TestEncProofSmall`, `TestB3EncProofBoundaries` |
| B4 | Case 1 pi_eval: other S, e_fl = 2^sigma + 1, u' coefficient 2, e' = 20, remainder > Q/2, D_j >= q_del (D_j + delta Q^-1 mod r), mod-Q quotient out of range, other h_c or h_pk, h_D not of D, wrong y_z | `pkg/zk/evalc1` `TestEvalC1Small`, `TestB4EvalC1Boundaries` |
| B5 | Case 2 pi_eval: c2,1 off relation (3), v coefficient 2, e1' = 20, w > w_max, Com(f) of other w | `pkg/zk/evalc2` `TestEvalC2Small`, `TestB5EvalC2Boundaries` |
| B6 | pi_dec: p off the partial decryption, e_fl = 2^sigma + 1, quotient out of range, another s, another h_c21 | `pkg/zk/decproof` `TestDecProofSmall`, `TestB6DecProofBoundaries` |
| B7 | A proof does not verify for another order ID | `pkg/zk/evalc1` `TestEvalC1Groth16Small`, `TestEvalC1OnChainSmall`; `pkg/zk/decproof` `TestDecProofOnChain`; `pkg/chain` `TestMarketCase2Rules`, `TestMarketCase1` |
| B8 | Proofs under keys the setup did not fix are refused by the counterparty and the contract; the buyer refuses keys whose constants are not the declared terms | `pkg/zk/keys` `TestB8ForeignKey`; `pkg/chain` `TestMarketRegistration`, `TestMarketCase2Rules`; `pkg/market` `TestE4BuyerChecks` |
| C1 | Case 1 noise attack (e_c = K X^l) refused by pi_member | `pkg/zk/member` `TestMemberSmall` |
| C2 | Case 2 key recovery (c2,1 = K X^(j-l)) refused by pi_eval | `pkg/zk/evalc2` `TestEvalC2Small` |
| C3 | A slot registered with a = 0 is refused by the buyer | `pkg/market` `TestC3SlotNotOnPublicCoin` |
| D1 | order refused: unregistered, retired, claimed, busy slot; T_ref - now outside [T_min, T_max]; wrong price | `pkg/chain` `TestMarketCase2Rules` |
| D2 | claim refused: now >= T_ref, no open order, failing proof, another order's proof, no blob, wrong y_z, commitment or proof_z, a blob that is not D | `pkg/chain` `TestMarketCase2Rules`, `TestMarketCase1` |
| D3 | claim pays the registered payout; slot claimed; event; a third party's copy pays the same address | `pkg/chain` `TestMarketCase2Rules`, `TestMarketCase1` |
| D4 | refund: refused before T_ref and after the claim, accepted after T_ref, refused twice | `pkg/chain` `TestMarketCase2Rules` |
| D5 | reject: refused for a non-seller and after the claim; returns the escrow at once | `pkg/chain` `TestMarketCase2Rules`; `pkg/market` `TestE5AbortPaths` |
| D6 | retire: no order afterwards; refused with an open order | `pkg/chain` `TestMarketCase2Rules` |
| D7 | re-order after a reject and after T_ref (before the refund), settled; the earlier refund still succeeds | `pkg/chain` `TestMarketCase2Rules` |
| D8 | budget: no more than q slots, one offer per Com(x), one claim per slot | `pkg/chain` `TestMarketRegistration`, `TestMarketCase2Rules` |
| D9 | claim included at T_ref - 1 succeeds; in block T_ref the claim fails and a refund in the same block succeeds | `pkg/chain` `TestMarketCase2Rules` (`Env.SendInOneBlock`) |
| E1 | honest exchange with proofs and settlement, all four sets | `pkg/market` `TestE1Flows`; `cmd/e2e` happy |
| E2 | the seller does not claim after T_ref - delta and rejects | `pkg/market` `TestE2SellerDeadline` (also after proving, with the unsent Case 2 partial decryption withdrawn) |
| E3 | the seller retires a slot whose claim was not included | `pkg/market` `TestE3E6LateClaim`; `cmd/e2e` late |
| E4 | the buyer does not order when the terms fail; T_ref - now < W | `pkg/market` `TestE4BuyerChecks` (W reduced to 200 blocks at its boundary) |
| E5 | failing buyer proof -> reject -> refund; silent seller -> refund after T_ref | `pkg/market` `TestE5AbortPaths`; `cmd/e2e` reject, refund |
| E6 | the buyer never uses a reverted claim's deliverable | `pkg/market` `TestE3E6LateClaim`; `cmd/e2e` late |
| F1 | packing round trip, every element below r_bls | `pkg/blob` `TestF1Packing` (68 and 43 bits) |
| F2 | circuit P_D(z) equals ComputeProof's y_z at 100 random z | `pkg/zk/gadgets` `TestF2BlobEvalMatchesKZG`; `pkg/chain` `TestMarketCase1` |
| F3 | off-chain vh equals the contract's blobhash(0) | `pkg/chain` `TestMarketCase1` (Claimed event) |
| F4 | a blob differing from D in one coefficient fails the claim | `pkg/chain` `TestMarketCase1` |
| F5 | a type-3 transaction with a cell-proof sidecar is included | `pkg/chain` `TestMarketCase1`; `pkg/blob` `TestBlobLink` |
| F6 | the buyer recovers D from the kept sidecar before T_ref | `pkg/chain` `TestMarketCase1`; `pkg/market` `TestE1Flows` |
| G1 | lattice estimator: >= 128 bits on the actual chains | `scripts/security_v8.py` under SageMath 10.9 in WSL (`scripts/setup_wsl_sage.sh`): 186.9, 263.7, 204.9, 239.4 bits |
| G2 | flood sampler range and uniformity | `pkg/rlwe` `TestG2FloodSampler` |
| G3 | constraints, proving time, memory, proof size per circuit | `*FullScale` tests with `FAIRHE_ZK_FULL=1 FAIRHE_ZK_PROVE=1 FAIRHE_ZK_REPS=5` -> `results/v8/zk.jsonl` |

Negative tests of B1-B6 build each wrong witness so that it breaks one
check only: the public values are recomputed for it (for example b for a
secret coefficient 2, c_san and D for a flood of 2^sigma + 1, h_D and y_z
for D_j + Q^-1), and the same construction with an admissible value (an
error of 19, a ternary coefficient, a flood of 2^sigma) is accepted.

Variants (the option labels O1 to O7 are explained in the README): O2 is tested by `pkg/zk/se` `TestEncryptAndExtract` (the
circuit accepts the native encryption, the extractor recovers the elements,
a ciphertext of other elements is refused), `TestCostModel`, and
`pkg/zk/member` `TestO2SE` (the extractor reads w from an accepting
pi_member, and an encryption of other weights is refused) and
`TestO2SEFullScale`. O5 changes what the DA layer holds; tests B1, C3 and
E1-E6 run with it. O1 is tested by `pkg/zk/sealv8` `TestSealRoundTrip`,
`TestSealCircuit` (an honest seal is accepted; a seal under another key,
another Y and h_D of another salt are refused) and `TestSealSize`, and by
`pkg/zk/evalc1` `TestSealedEvalC1` and `pkg/zk/decproof`
`TestSealedDecProof` (the sealed correctness proof accepts the honest
claim, shares h_D with pi_seal, and refuses h_D of another value); the
`...FullScale` variants measure the three circuits at full scale.

O6 is tested by `pkg/blob` `TestPackBytes` and `TestSidecarAndCheck`,
`pkg/chain` `TestBlobBoard` (each digest recorded with the versioned hashes
of its blobs and the poster; counts that leave a blob unnamed, name a
missing blob, contain a zero or do not match the digests revert), and
`pkg/market` `TestPackPolys`, `TestO6Flows` (both cases end to end on blob
data; a posting by another account under the order's digest is ignored),
`TestO6AbortPaths` (a failing proof and an input never posted are
rejected) and `TestO6Retention` (a slot past W is unavailable until it is
posted again); `cmd/e2e -board blob` runs the four scenarios on blob data.

O7 is tested by `pkg/market` `TestO7Archive` (the buyer decodes from the
archive after W, when the network no longer serves the blob; a restarted
archive resumes from its cursor; a changed archived blob fails the check;
an archive that syncs after W misses the blob) and measured by
`TestO7ArchiveCost` and the `cmd/e2e` scenario `archive`.
