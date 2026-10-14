// Command e2e runs the fair exchange end to end on the simulated chain:
// for each parameter set it deploys the claim verifier and
// the market, and runs the scenarios
//
//	happy   registration, order, checks, claim, decoding
//	reject  the buyer's proof fails; the seller rejects and the escrow returns
//	refund  the seller stays offline; the buyer refunds after T_ref
//	late    the claim lands at T_ref; it fails, the seller retires the slot
//	        and the buyer refunds
//	archive (Case 1, option O7) the retention window W is cut to 128
//	        blocks; an archive stores the claim's blob before W ends and
//	        the buyer decodes from it after W
//
// recording per-stage times, per-transaction gas and calldata (the ledger
// records), the blobs and the communication in results/v8/e2e.jsonl. The
// happy and archive scenarios run -reps times, each on a fresh chain, for
// medians. With -board blob the bulky values travel as blob data through
// BlobBoard instead of the DA layer (option O6; the rows carry "board":
// "blob"):
//
//	go run ./cmd/e2e -scale small
//	go run ./cmd/e2e -scale full -params case2_bfv -scenarios happy -reps 5
//	go run ./cmd/e2e -scale full -board blob -scenarios happy -reps 5
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fairhe/pkg/blob"
	"fairhe/pkg/chain"
	"fairhe/pkg/clock"
	"fairhe/pkg/market"
	"fairhe/pkg/onchain"
	"fairhe/pkg/rlwe"
	"fairhe/pkg/valuation"
	"fairhe/pkg/zk/registry"
	"fairhe/pkg/zk/zkmeasure"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Row is one scenario run.
type Row struct {
	Time      string             `json:"time"`
	Params    string             `json:"params"`
	Scale     string             `json:"scale"`
	Scenario  string             `json:"scenario"`
	Board     string             `json:"board,omitempty"` // "blob" for option O6; the DA layer otherwise
	Outcome   string             `json:"outcome"`
	Correct   bool               `json:"correct"`
	AbsError  float64            `json:"abs_error,omitempty"`
	LogTau    float64            `json:"log2_tau,omitempty"`
	StagesS   map[string]float64 `json:"stages_s"`
	Rep       int                `json:"rep,omitempty"`
	Gas       map[string]uint64  `json:"gas"`
	Calldata  map[string]int     `json:"calldata_bytes,omitempty"`
	BlobGas   uint64             `json:"blob_gas,omitempty"`
	Blobs     int                `json:"blobs,omitempty"`
	Bytes     map[string]int     `json:"bytes,omitempty"`
	Note      string             `json:"note,omitempty"`
	GitCommit string             `json:"git_commit"`
}

func main() {
	scale := flag.String("scale", "small", "small or full")
	paramsFlag := flag.String("params", "case1_bfv,case1_ckks,case2_bfv,case2_ckks", "parameter sets")
	scenarios := flag.String("scenarios", "happy,reject,refund,late", "scenarios")
	reps := flag.Int("reps", 1, "runs of the happy scenario")
	boardFlag := flag.String("board", "da", "where the bulky values go: da (the DA layer) or blob (option O6)")
	keyDir := flag.String("keys", "", "key directory (default keys/<scale>)")
	out := flag.String("out", filepath.Join("results", "v8", "e2e.jsonl"), "JSONL output")
	flag.Parse()
	sc := registry.Scale(*scale)
	if *boardFlag != "da" && *boardFlag != "blob" {
		log.Fatalf("unknown board %q", *boardFlag)
	}
	dir := *keyDir
	if dir == "" {
		dir = filepath.Join("keys", *scale)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		log.Fatal(err)
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	// Load the KZG trusted setup once, outside the measured stages.
	if _, err := blob.NewLink([]*big.Int{big.NewInt(1)}, [32]byte{}); err != nil {
		log.Fatal(err)
	}
	failed := false
	for _, params := range strings.Split(*paramsFlag, ",") {
		start := time.Now()
		tk, err := market.LoadOrSetupToolkit(sc, params, dir)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("== %s (%s): toolkit ready in %.1fs\n", params, *scale, time.Since(start).Seconds())
		for _, scn := range strings.Split(*scenarios, ",") {
			if scn == "archive" && tk.Case() != rlwe.Case1 {
				continue // the Case 2 deliverable is in the Claimed event
			}
			n := 1
			if scn == "happy" || scn == "archive" {
				n = *reps
			}
			for rep := 1; rep <= n; rep++ {
				row, err := run(tk, scn, *boardFlag == "blob")
				if err != nil {
					log.Fatalf("%s/%s: %v", params, scn, err)
				}
				row.Time, row.Params, row.Scale, row.Scenario = time.Now().UTC().Format(time.RFC3339), params, *scale, scn
				row.Rep, row.GitCommit = rep, zkmeasure.GitCommit()
				if err := enc.Encode(row); err != nil {
					log.Fatal(err)
				}
				fmt.Printf("   %-7s %d %-9s correct=%-5v gas=%v blobs=%d\n", scn, rep, row.Outcome, row.Correct, row.Gas, row.Blobs)
				if !row.Correct {
					failed = true
				}
			}
		}
	}
	if failed {
		os.Exit(1)
	}
}

type world struct {
	tk                    *market.Toolkit
	env                   *chain.Env
	m                     *chain.Market
	seller, buyer, payout *chain.Account
	da                    *market.DA
	bb                    *market.BlobBoard // option O6, else nil
	board                 market.Board
	net                   *market.BlobNet
	row                   *Row
}

func newWorld(tk *market.Toolkit, row *Row, blobBoard bool) (*world, error) {
	seller, _ := chain.NewAccount()
	buyer, _ := chain.NewAccount()
	payout, _ := chain.NewAccount()
	env, err := chain.NewEnv(seller, buyer)
	if err != nil {
		return nil, err
	}
	root, err := onchain.RepoRoot()
	if err != nil {
		return nil, err
	}
	claim, offchain := tk.Dec, [][32]byte{tk.Key.VKID()}
	if tk.Case() == rlwe.Case1 {
		claim = tk.EvalC1
		offchain = append(offchain, tk.Member.VKID())
	} else {
		offchain = append(offchain, tk.Enc.VKID(), tk.EvalC2.VKID())
	}
	vcon, err := chain.LoadContract(filepath.Join(root, claim.Rec.VerifierArtifact))
	if err != nil {
		return nil, err
	}
	vaddr, vr, err := env.Deploy(seller, vcon)
	if err != nil {
		return nil, err
	}
	row.Gas["deploy_verifier"] = vr.GasUsed
	mcon, err := chain.LoadContract(filepath.Join(root, "contracts", "out", "FairExchangeMarket.json"))
	if err != nil {
		return nil, err
	}
	m, mr, err := chain.DeployMarket(env, seller, mcon, [][32]byte{claim.VKID()}, []common.Address{vaddr}, offchain)
	if err != nil {
		return nil, err
	}
	row.Gas["deploy_market"] = mr.GasUsed
	w := &world{tk: tk, env: env, m: m, seller: seller, buyer: buyer, payout: payout,
		da: market.NewDA(), net: market.NewBlobNet(market.RetentionBlocks), row: row}
	w.board = w.da
	if blobBoard {
		bcon, err := chain.LoadContract(filepath.Join(root, "contracts", "out", "BlobBoard.json"))
		if err != nil {
			return nil, err
		}
		b, br, err := chain.DeployBoard(env, seller, bcon)
		if err != nil {
			return nil, err
		}
		row.Gas["deploy_board"] = br.GasUsed
		w.bb = market.NewBlobBoard(b, w.net)
		w.board = w.bb
	}
	return w, nil
}

// inputs returns the seller's data and the buyer's weights for the scale.
func inputs(tk *market.Toolkit) (S, w []int64) {
	cl := tk.Class
	if tk.Scale == registry.Full {
		ds := valuation.Generate(2026, valuation.NMax)
		if tk.P.Scheme() == rlwe.BFV {
			return valuation.Stats(ds), valuation.RandomWeights(1004, valuation.WMax)
		}
		return valuation.StatsFixed(ds), valuation.RandomWeights(1004, valuation.WMaxFixedInt)
	}
	S = make([]int64, cl.M())
	for k := range S {
		S[k] = int64(1)<<(cl.XBits-2) + int64(13*k)
	}
	return S, []int64{cl.WMax / 3, -cl.WMax / 5}
}

func run(tk *market.Toolkit, scn string, blobBoard bool) (*Row, error) {
	row := &Row{StagesS: map[string]float64{}, Gas: map[string]uint64{}, Calldata: map[string]int{}}
	if blobBoard {
		row.Board = "blob"
	}
	w, err := newWorld(tk, row, blobBoard)
	if err != nil {
		return nil, err
	}
	defer w.env.Close()
	S, wts := inputs(tk)
	trace := func(stage string, d time.Duration) { row.StagesS[stage] += d.Seconds() }
	// Several transactions of one name (the posts of option O6) add up.
	gas := func(tx string, r *types.Receipt) {
		row.Gas[tx] += r.GasUsed
		if r.BlobGasUsed > 0 {
			row.BlobGas += r.BlobGasUsed
			row.Blobs += int(r.BlobGasUsed / (1 << 17)) // 131,072 blob gas per blob
		}
		if t, _, err := w.env.Client.TransactionByHash(context.Background(), r.TxHash); err == nil {
			row.Calldata[tx] += len(t.Data())
		}
	}
	delta := uint64(32)
	if scn == "late" {
		delta = 0 // a seller that waits until the last block
	}
	if scn == "archive" {
		w.net.W = archiveW // set before the buyer, whose W is the network's
	}
	s, err := market.NewSeller(w.seller, w.payout.Addr, w.m, w.board, w.net, tk, S, delta)
	if err != nil {
		return nil, err
	}
	s.Trace, s.Gas = trace, gas
	// T_min covers checking, computing and proving (8 blocks, 96 s) plus delta.
	if _, err := s.Register(1, big.NewInt(1e15), delta+8, 7200); err != nil {
		return nil, err
	}
	b := market.NewBuyer(w.buyer, w.m, w.board, w.net, tk)
	b.Trace, b.Gas = trace, gas
	if tk.Case() == rlwe.Case1 {
		if _, err := b.RegisterKey(0); err != nil {
			return nil, err
		}
	}
	if err := b.CheckOffer(s.OfferID); err != nil {
		return nil, err
	}
	tRefDelta := uint64(80)
	if scn == "late" {
		tRefDelta = 40
	}
	if scn == "reject" && w.bb != nil { // the buyer posts a corrupted proof
		w.bb.Tamper = func(it *market.Item) { it.Proof[len(it.Proof)/2] ^= 1 }
	}
	id, _, err := b.Order(s.OfferID, 1, wts, tRefDelta)
	if w.bb != nil {
		w.bb.Tamper = nil
	}
	if err != nil {
		return nil, err
	}
	switch scn {
	case "reject":
		if w.bb != nil {
			break
		}
		oi, _ := w.m.OrderInfo(id)
		label := market.LabelPiEval
		if tk.Case() == rlwe.Case1 {
			label = market.LabelPiMember
		}
		key := market.ProofKey(oi.HInput, label)
		p, _ := w.da.Get(key)
		p[len(p)/2] ^= 1
		w.da.Put(key, p)
	case "refund":
		w.env.Mine(int(tRefDelta) + 1)
	case "late":
		oi, _ := w.m.OrderInfo(id)
		now, _ := w.env.BlockNumber()
		w.env.Mine(int(oi.TRef - now - 1))
	}
	if scn != "refund" {
		out, why, err := s.Handle(id)
		if err != nil {
			return nil, err
		}
		row.Outcome, row.Note = out.String(), why
	} else {
		row.Outcome = "seller offline"
	}
	if scn == "late" {
		oi, _ := w.m.OrderInfo(id)
		now, _ := w.env.BlockNumber()
		if now < oi.TRef {
			w.env.Mine(int(oi.TRef - now))
		}
	}
	var archived bool
	if scn == "archive" {
		archived, err = archiveAndWait(w, b, id, trace)
		if b.Archive != nil {
			defer os.RemoveAll(b.Archive.Dir)
		}
		if err != nil {
			return nil, err
		}
	}
	res, err := b.Await(id)
	if err != nil {
		return nil, err
	}
	switch scn {
	case "happy", "archive":
		if res == nil || res.Refunded || (scn == "archive" && !archived) {
			return row, nil
		}
		row.Bytes = sizes(w, id)
		if scn == "archive" {
			row.Bytes["archive_blob"] = 131072
		}
		ip := valuation.InnerProduct(tk.Class.Expand(wts), S)
		rep := tk.P.CheckMargins(tk.ClassBounds())
		if tk.P.Scheme() == rlwe.BFV {
			row.Correct = res.Value.Cmp(ip) == 0
		} else {
			want := new(big.Rat).SetFrac(ip, new(big.Int).Lsh(big.NewInt(1), 2*valuation.FracBits))
			diff, _ := new(big.Rat).Sub(res.Real, want).Float64()
			row.AbsError, row.LogTau = math.Abs(diff), rep.LogTau
			row.Correct = math.Log2(math.Abs(diff)) <= rep.LogTau
		}
	case "reject":
		st, _ := w.m.OrderState(id)
		row.Correct = row.Outcome == "rejected" && st == 4
	case "refund", "late":
		row.Correct = res != nil && res.Refunded && (scn == "refund" || row.Outcome == "retired")
	default:
		return nil, fmt.Errorf("unknown scenario %q", scn)
	}
	return row, nil
}

// sizes returns the communication of one exchange: compact sizes of the
// values on the board, the serialised off-chain proofs, the claim's
// deliverable and its on-chain proof; with the blob board also each
// posting's payload (value and proof) and blobs.
func sizes(w *world, orderID *big.Int) map[string]int {
	tk, p := w.tk, w.tk.P
	n, qb := p.N(), tk.QBits()
	poly := func(k int) int { return (k*n*qb + 7) / 8 }
	out := map[string]int{}
	posted := func(msg, proofName string, poster common.Address, digest [32]byte, label string) {
		if _, pr, err := w.board.Fetch(poster, digest, label); err == nil {
			out[proofName] = len(pr)
		}
		if w.bb != nil {
			if st, ok := w.bb.Stat(poster, digest); ok {
				out["post_"+msg+"_payload"], out["post_"+msg+"_blobs"] = st.Bytes, st.Blobs
			}
		}
	}
	oi, err := w.m.OrderInfo(orderID)
	if err != nil {
		return out
	}
	if tk.Case() == rlwe.Case1 {
		keyID, _ := w.m.OrderKeyID(orderID)
		_, _, hPk, _, _ := w.m.BuyerKey(keyID)
		out["buyer_key"] = poly(1) // b; a is the public coin (option O5)
		posted("key", "pi_key", w.buyer.Addr, hPk, market.LabelPiKey)
		out["order_ciphertext"] = poly(1) + market.SeedBytes // c0 and the seed of a'
		posted("order", "pi_member", w.buyer.Addr, oi.HInput, market.LabelPiMember)
		dbits := new(big.Int).Sub(p.QDel(), big.NewInt(1)).BitLen()
		out["deliverable"] = ((n+1)*dbits + 7) / 8
		out["blob"] = 131072
		out["claim_proof"] = 384 + 2*96 // BLS12-381 Groth16 with one commitment
	} else {
		si, _ := w.m.SlotInfo(oi.OfferID, oi.Slot)
		out["slot_key"] = poly(1) // b; a is the public coin (option O5)
		out["slot_c1"] = poly(1)  // c1,0; c1,1 is the public coin
		posted("slot_key", "pi_key", w.seller.Addr, si.HPk, market.LabelPiKey)
		posted("slot_c1", "pi_enc", w.seller.Addr, si.HC1, market.LabelPiEnc)
		out["order_c21"] = poly(1)
		posted("order", "pi_eval", w.buyer.Addr, oi.HInput, market.LabelPiEval)
		out["deliverable"] = (qb + 7) / 8
		out["claim_proof"] = 256 + 2*64 // BN254 Groth16 with one commitment
	}
	return out
}

// archiveW is the retention window of the archive scenario, in blocks: W cut
// to test its boundary, above T_ref - T_order plus the
// buyer's retrieval margin.
const archiveW = 128

// archiveAndWait runs an archive after the claim (option O7): it syncs while
// the claim's blob is retained, then the chain moves past W so that the
// network no longer serves the blob and the buyer reads it from the
// archive. It reports whether the archive stored the blob and the network
// had dropped it.
func archiveAndWait(w *world, b *market.Buyer, orderID *big.Int, trace func(string, time.Duration)) (bool, error) {
	dir, err := os.MkdirTemp("", "fairhe-archive-")
	if err != nil {
		return false, err
	}
	arch, err := market.OpenArchive(dir)
	if err != nil {
		return false, err
	}
	start := clock.Now()
	rep, err := arch.Sync(w.m, w.net)
	trace("archive.sync", clock.Since(start))
	if err != nil {
		return false, err
	}
	w.env.Mine(int(w.net.W))
	ev, err := w.m.ClaimOf(orderID)
	if err != nil || ev == nil {
		return false, err
	}
	now, err := w.env.BlockNumber()
	if err != nil {
		return false, err
	}
	_, retained := w.net.Fetch(ev["versionedHash"].([32]byte), now)
	b.Archive = arch
	return rep.Stored == 1 && !retained, nil
}
