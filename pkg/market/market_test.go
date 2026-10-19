package market

// Scenario tests of the state machines on the simulated chain with reduced
// proofs, numbered as in docs/tests.md: E1-E8
// (state machines end to end; E7 and E8 on the seller side: posted values
// that are not canonical residues, and a claim that would revert), C3 and
// B1 on the verifier side (a key that is not on its public coin), and B8 on
// the buyer side (an offer that names verification keys other than those
// fixed for its terms). They set up small keys on the fly and need python
// with py-solc-x.

import (
	"crypto/rand"
	"math"
	"math/big"
	"math/bits"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"fairhe/pkg/chain"
	"fairhe/pkg/hashes"
	"fairhe/pkg/onchain"
	"fairhe/pkg/rlwe"
	"fairhe/pkg/valuation"
	"fairhe/pkg/zk/evalc1"
	"fairhe/pkg/zk/keyproof"
	"fairhe/pkg/zk/keys"
	"fairhe/pkg/zk/member"
	"fairhe/pkg/zk/registry"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tuneinsight/lattigo/v6/ring"
)

type world struct {
	t                     *Toolkit
	env                   *chain.Env
	market                *chain.Market
	seller, buyer, payout *chain.Account
	da                    *DA
	net                   *BlobNet
	board                 Board // the DA layer unless useBlobBoard is called
}

// newWorld deploys a market whose setup fixed the keys of the toolkit of
// params and of the extra toolkits.
func newWorld(t *testing.T, params string, extra ...*Toolkit) *world {
	t.Helper()
	if testing.Short() {
		t.Skip("needs python with py-solc-x")
	}
	return deploy(t, toolkit(t, params), nil, extra...)
}

// claimCircuit returns the circuit of a toolkit's claim proof.
func claimCircuit(k *Toolkit) *Circuit {
	if k.Case() == rlwe.Case1 {
		return k.EvalC1
	}
	return k.Dec
}

// deploy deploys a market whose setup fixed the keys of tk and of the extra
// toolkits. If wrong is not nil, the verifier of its claim key (another
// setup of the same set) serves tk's claim key, so that tk's claims pass
// every off-chain check and revert on-chain.
func deploy(t *testing.T, tk, wrong *Toolkit, extra ...*Toolkit) *world {
	t.Helper()
	seller, _ := chain.NewAccount()
	buyer, _ := chain.NewAccount()
	payout, _ := chain.NewAccount()
	env, err := chain.NewEnv(seller, buyer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { env.Close() })
	root, _ := onchain.RepoRoot()
	var claimIDs, offchain [][32]byte
	var verifiers []common.Address
	for i, k := range append([]*Toolkit{tk}, extra...) {
		claim, off := claimCircuit(k), [][32]byte{k.Key.VKID()}
		if k.Case() == rlwe.Case1 {
			off = append(off, k.Member.VKID())
		} else {
			off = append(off, k.Enc.VKID(), k.EvalC2.VKID())
		}
		artifact := claim.Rec.VerifierArtifact
		if i == 0 && wrong != nil {
			artifact = claimCircuit(wrong).Rec.VerifierArtifact
		}
		vcon, err := chain.LoadContract(filepath.Join(root, artifact))
		if err != nil {
			t.Fatal(err)
		}
		vaddr, _, err := env.Deploy(seller, vcon)
		if err != nil {
			t.Fatal(err)
		}
		claimIDs, verifiers, offchain = append(claimIDs, claim.VKID()), append(verifiers, vaddr), append(offchain, off...)
	}
	mcon, err := chain.LoadContract(filepath.Join(root, "contracts", "out", "FairExchangeMarket.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := chain.DeployMarket(env, seller, mcon, claimIDs, verifiers, offchain)
	if err != nil {
		t.Fatal(err)
	}
	da := NewDA()
	return &world{t: tk, env: env, market: m, seller: seller, buyer: buyer, payout: payout, da: da, net: NewBlobNet(RetentionBlocks), board: da}
}

func toolkit(t *testing.T, params string) *Toolkit {
	t.Helper()
	tk, err := SetupToolkit(registry.Small, params, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return tk
}

func (w *world) data() []int64 {
	S := make([]int64, w.t.Class.M())
	for k := range S {
		S[k] = int64(1)<<(w.t.Class.XBits-2) + int64(13*k)
	}
	return S
}

func (w *world) newSeller(t *testing.T, q uint16, delta uint64) *Seller {
	t.Helper()
	s, err := NewSeller(w.seller, w.payout.Addr, w.market, w.board, w.net, w.t, w.data(), delta)
	if err != nil {
		t.Fatal(err)
	}
	// T_min covers checking, computing and proving (8 blocks) plus delta.
	if rcpt, err := s.Register(q, big.NewInt(1e15), delta+8, 7200); err != nil || rcpt.Status != 1 {
		t.Fatalf("register: %v", err)
	}
	return s
}

func (w *world) newBuyer(t *testing.T) *Buyer {
	t.Helper()
	b := NewBuyer(w.buyer, w.market, w.board, w.net, w.t)
	if w.t.Case() == rlwe.Case1 {
		if _, err := b.RegisterKey(0); err != nil {
			t.Fatal(err)
		}
	}
	return b
}

// checkResult compares the buyer's result with f: exact for BFV, within
// tau for CKKS.
func (w *world) checkResult(t *testing.T, res *Result, wts []int64) {
	t.Helper()
	ip := valuation.InnerProduct(w.t.Class.Expand(wts), w.data())
	if res == nil || res.Refunded {
		t.Fatalf("%s: no result (%+v)", w.t.Name, res)
	}
	if w.t.P.Scheme() == rlwe.BFV {
		if res.Value.Cmp(ip) != 0 {
			t.Fatalf("%s: decoded %s, want %s", w.t.Name, res.Value, ip)
		}
		return
	}
	want := new(big.Rat).SetFrac(ip, new(big.Int).Lsh(big.NewInt(1), 2*valuation.FracBits))
	diff, _ := new(big.Rat).Sub(res.Real, want).Float64()
	if tau := w.t.P.CheckMargins(w.t.ClassBounds()).LogTau; math.Log2(math.Abs(diff)) > tau {
		t.Fatalf("%s: error 2^%.2f above tau 2^%.2f", w.t.Name, math.Log2(math.Abs(diff)), tau)
	}
}

// TestE1Flows: honest exchanges of all four sets with proofs and on-chain
// settlement: registration, order, claim, recovery, the CKKS sets
// included. In Case 2 the buyer deletes c2,0 after decoding and the seller
// erases the slot's secret once it is claimed.
func TestE1Flows(t *testing.T) {
	for _, params := range []string{"case1_bfv", "case1_ckks", "case2_bfv", "case2_ckks"} {
		w := newWorld(t, params)
		s := w.newSeller(t, 2, 32)
		b := w.newBuyer(t)
		if err := b.CheckOffer(s.OfferID); err != nil {
			t.Fatal(err)
		}
		wts := []int64{-5, 9}
		id, _, err := b.Order(s.OfferID, 1, wts, 80)
		if err != nil {
			t.Fatal(err)
		}
		if res, err := b.Await(id); err != nil || res != nil {
			t.Fatalf("%s: result before the claim: %v %v", params, res, err)
		}
		if w.t.Case() == rlwe.Case2 && !b.HoldsC20(id) {
			t.Fatal("buyer does not hold c2,0 after ordering")
		}
		out, why, err := s.Handle(id)
		if err != nil || out != Claimed {
			t.Fatalf("%s: seller: %v %s %v", params, out, why, err)
		}
		res, err := b.Await(id)
		if err != nil {
			t.Fatal(err)
		}
		w.checkResult(t, res, wts)
		if si, _ := w.market.SlotInfo(s.OfferID, 1); si.State != 1 {
			t.Fatalf("%s: slot 1 not claimed", params)
		}
		if w.t.Case() == rlwe.Case2 {
			if b.HoldsC20(id) {
				t.Fatal("c2,0 kept after decoding")
			}
			if _, kept := s.slots[1]; kept {
				t.Fatal("the seller kept the secret of a claimed slot")
			}
		}
	}
}

// TestE2SellerDeadline: the seller does not claim within delta blocks of
// the refund time, neither before computing nor after proving, and rejects;
// a Case 2 partial decryption that was computed but not sent is withdrawn,
// so the slot serves the next order.
func TestE2SellerDeadline(t *testing.T) {
	for _, params := range []string{"case1_bfv", "case2_bfv"} {
		w := newWorld(t, params)
		s := w.newSeller(t, 1, 32)
		b := w.newBuyer(t)
		wts := []int64{3, -4}
		id, _, err := b.Order(s.OfferID, 1, wts, s.Delta+8)
		if err != nil {
			t.Fatal(err)
		}
		w.env.Mine(9) // the seller comes to the order late
		if out, why, _ := s.Handle(id); out != Rejected {
			t.Fatalf("%s: expected a reject for lack of time, got %v %s", params, out, why)
		}
		id, _, err = b.Order(s.OfferID, 1, wts, 80)
		if err != nil {
			t.Fatal(err)
		}
		oi, _ := w.market.OrderInfo(id)
		s.AfterProve = func() { // proving took until delta blocks before T_ref
			now, _ := w.env.BlockNumber()
			w.env.Mine(int(oi.TRef - s.Delta - now))
		}
		if out, why, _ := s.Handle(id); out != Rejected {
			t.Fatalf("%s: expected a reject after proving, got %v %s", params, out, why)
		}
		if st, _ := w.market.OrderState(id); st != 4 {
			t.Fatalf("%s: order state %d after the reject", params, st)
		}
		if w.t.Case() == rlwe.Case2 && s.slots[1].Used() {
			t.Fatal("the unsent partial decryption was not withdrawn")
		}
		s.AfterProve = nil
		id, _, err = b.Order(s.OfferID, 1, wts, 80)
		if err != nil {
			t.Fatal(err)
		}
		if out, why, err := s.Handle(id); err != nil || out != Claimed {
			t.Fatalf("%s: the slot did not serve the next order: %v %s %v", params, out, why, err)
		}
		res, err := b.Await(id)
		if err != nil {
			t.Fatal(err)
		}
		w.checkResult(t, res, wts)
	}
}

// TestE3E6LateClaim: a seller that claims in the last block before the
// refund time (delta = 0) sees its claim included at T_ref and reverted; it
// retires the slot and erases its secret (E3). The buyer, whose order has no
// accepted claim, refunds and never uses the reverted claim's deliverable,
// which was public (E6).
func TestE3E6LateClaim(t *testing.T) {
	for _, params := range []string{"case1_bfv", "case2_bfv"} {
		w := newWorld(t, params)
		s := w.newSeller(t, 1, 0)
		b := w.newBuyer(t)
		id, _, err := b.Order(s.OfferID, 1, []int64{2, 2}, 40)
		if err != nil {
			t.Fatal(err)
		}
		oi, _ := w.market.OrderInfo(id)
		now, _ := w.env.BlockNumber()
		w.env.Mine(int(oi.TRef - now - 1))
		out, why, err := s.Handle(id)
		if err != nil || out != Retired {
			t.Fatalf("%s: expected a retired slot, got %v %s %v", params, out, why, err)
		}
		if si, _ := w.market.SlotInfo(s.OfferID, 1); si.State != 2 {
			t.Fatalf("%s: slot state %d after retire", params, si.State)
		}
		if _, kept := s.slots[1]; kept {
			t.Fatal("the seller kept the secret of a retired slot")
		}
		res, err := b.Await(id)
		if err != nil || res == nil || !res.Refunded {
			t.Fatalf("%s: expected a refund, got %+v %v", params, res, err)
		}
	}
}

// TestE4BuyerChecks: the buyer pays nothing for an order outside
// [T_min, T_max] or beyond the retention window W (checked at its boundary
// with W reduced), and does not order from an offer whose
// terms are not its own or that names verification keys other than those
// fixed for these terms (B8): here the claim key of the Case 2 CKKS set,
// also fixed in the contract.
func TestE4BuyerChecks(t *testing.T) {
	if testing.Short() {
		t.Skip("needs python with py-solc-x")
	}
	other := toolkit(t, "case2_ckks")
	w := newWorld(t, "case2_bfv", other)
	s := w.newSeller(t, 3, 32)
	b := w.newBuyer(t)
	if err := b.CheckOffer(s.OfferID); err != nil {
		t.Fatal(err)
	}
	balance := func() *big.Int { v, _ := w.env.BalanceAt(w.buyer.Addr); return v }
	wts := []int64{1, 1}
	before := balance()
	for _, delta := range []uint64{3, 7201} {
		if _, rcpt, err := b.Order(s.OfferID, 1, wts, delta); err == nil || rcpt != nil {
			t.Fatalf("ordered %d blocks ahead, outside [4, 7200]", delta)
		}
	}
	b.W = 200
	if _, rcpt, err := b.Order(s.OfferID, 1, wts, 200-RetrievalMargin); err == nil || rcpt != nil {
		t.Fatal("ordered with T_ref - now = W - margin")
	}
	if balance().Cmp(before) != 0 {
		t.Fatal("refused orders cost the buyer")
	}
	if _, _, err := b.Order(s.OfferID, 1, wts, 200-RetrievalMargin-1); err != nil {
		t.Fatalf("refused T_ref - now = W - margin - 1: %v", err)
	}
	// Offers the buyer must not take: other terms, other fixed keys.
	register := func(args chain.OfferArgs) *big.Int {
		dig := [][32]byte{{1}}
		id, rcpt, err := w.market.RegisterOffer(w.seller, args, dig, dig, dig)
		if err != nil || rcpt.Status != 1 {
			t.Fatalf("register: %v", err)
		}
		return id
	}
	args := chain.OfferArgs{CaseId: 2, Payout: w.payout.Addr, Price: big.NewInt(1e15), TMin: 4, TMax: 7200, Q: 1,
		Terms: w.t.Terms(), ClaimVk: w.t.Dec.VKID(), KeyVk: w.t.Key.VKID(), InputVk: w.t.Enc.VKID()}
	bad := args
	bad.ComX, bad.Terms = [32]byte{0xa1}, [32]byte(crypto.Keccak256([]byte("other terms")))
	if err := b.CheckOffer(register(bad)); err == nil || !strings.Contains(err.Error(), "terms") {
		t.Fatalf("E4: accepted other terms (%v)", err)
	}
	bad = args
	bad.ComX, bad.ClaimVk = [32]byte{0xa2}, other.Dec.VKID()
	if err := b.CheckOffer(register(bad)); err == nil || !strings.Contains(err.Error(), "verification keys") {
		t.Fatalf("B8: accepted the claim key of another set (%v)", err)
	}
}

// TestE5AbortPaths: the seller rejects an order whose proof fails or whose
// input is unavailable and the escrow returns at once; a buyer whose order
// is not claimed refunds after T_ref.
func TestE5AbortPaths(t *testing.T) {
	w := newWorld(t, "case2_bfv")
	s := w.newSeller(t, 3, 32)
	b := w.newBuyer(t)
	balance := func() *big.Int { v, _ := w.env.BalanceAt(w.buyer.Addr); return v }

	// A failing pi_eval: corrupt the proof in the DA layer.
	id, _, err := b.Order(s.OfferID, 1, []int64{1, 2}, 80)
	if err != nil {
		t.Fatal(err)
	}
	oi, _ := w.market.OrderInfo(id)
	key := ProofKey(oi.HInput, LabelPiEval)
	p, _ := w.da.Get(key)
	p[len(p)/2] ^= 1
	w.da.Put(key, p)
	before := balance()
	out, why, err := s.Handle(id)
	if err != nil || out != Rejected {
		t.Fatalf("expected a reject on a bad proof, got %v %s %v", out, why, err)
	}
	if new(big.Int).Sub(balance(), before).Cmp(big.NewInt(1e15)) != 0 {
		t.Fatal("reject did not return the escrow at once")
	}
	t.Logf("rejected: %s", why)

	// An unavailable input.
	id, _, err = b.Order(s.OfferID, 1, []int64{1, 2}, 80)
	if err != nil {
		t.Fatal(err)
	}
	oi, _ = w.market.OrderInfo(id)
	w.da.Delete(oi.HInput)
	if out, why, _ := s.Handle(id); out != Rejected {
		t.Fatalf("expected a reject on missing data, got %v %s", out, why)
	}

	// A seller that stays offline: the buyer refunds after T_ref.
	id, _, err = b.Order(s.OfferID, 3, []int64{4, 4}, 40)
	if err != nil {
		t.Fatal(err)
	}
	if res, _ := b.Await(id); res != nil {
		t.Fatal("result before the refund time")
	}
	w.env.Mine(41)
	res, err := b.Await(id)
	if err != nil || res == nil || !res.Refunded {
		t.Fatalf("expected a refund, got %+v %v", res, err)
	}
}

// TestC3SlotNotOnPublicCoin: a seller registers a Case 2 slot whose key has
// a = 0 (b = e_pk, consistent digests, and valid pi_key and pi_enc for that
// key); the buyer's recomputation of the public coins refuses the offer.
func TestC3SlotNotOnPublicCoin(t *testing.T) {
	w := newWorld(t, "case2_bfv")
	s, err := NewSeller(w.seller, w.payout.Addr, w.market, w.board, w.net, w.t, w.data(), 32)
	if err != nil {
		t.Fatal(err)
	}
	p := w.t.P
	comX := s.ComX()
	_, c11, err := p.SlotCoins(w.seller.Addr.Bytes(), comX[:], 1)
	if err != nil {
		t.Fatal(err)
	}
	sk, pk, kw, err := p.KeyGen(p.RingQ().NewPoly(), rand.Reader) // a = 0
	if err != nil {
		t.Fatal(err)
	}
	c1, ew, err := p.EncryptSK(sk, s.sbar(), c11, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	eta := make([]byte, hashes.SaltBytes)
	rand.Read(eta)
	hs, err := hashes.DigSecret(hashes.BN254, rlwe.LabelHS, sk.S, eta)
	if err != nil {
		t.Fatal(err)
	}
	slot := &rlwe.Slot{Index: 1, SK: sk, PK: pk, C1: c1, Eta: eta, HS: hs, KeyWitness: kw, EncWitness: ew}
	hPk, hC1, err := s.publishSlot(slot)
	if err != nil {
		t.Fatal(err)
	}
	id, rcpt, err := w.market.RegisterOffer(w.seller, chain.OfferArgs{CaseId: 2, Payout: w.payout.Addr, ComX: comX,
		Price: big.NewInt(1e15), TMin: 4, TMax: 7200, Q: 1, Terms: w.t.Terms(), ClaimVk: w.t.Dec.VKID(),
		KeyVk: w.t.Key.VKID(), InputVk: w.t.Enc.VKID()}, [][32]byte{hPk}, [][32]byte{hC1}, [][32]byte{hashes.Bytes32(hs)})
	if err != nil || rcpt.Status != 1 {
		t.Fatalf("register: %v", err)
	}
	b := w.newBuyer(t)
	if err := b.CheckOffer(id); err == nil || !strings.Contains(err.Error(), "public coin") {
		t.Fatalf("the buyer accepted a slot key with a = 0 (%v)", err)
	}
}

// TestB1BuyerKeyNotOnPublicCoin: a Case 1 buyer registers a key whose a is
// fresh randomness instead of H_coin(buyer, index), with a valid pi_key for
// it; the seller's recomputation of a rejects the order.
func TestB1BuyerKeyNotOnPublicCoin(t *testing.T) {
	w := newWorld(t, "case1_bfv")
	s := w.newSeller(t, 1, 32)
	b := NewBuyer(w.buyer, w.market, w.board, w.net, w.t)
	p := w.t.P
	a, err := p.FreshUniform(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sk, pk, kw, err := p.KeyGen(a, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	eta := make([]byte, hashes.SaltBytes)
	rand.Read(eta)
	kc := w.t.Key.Entry.Config.(keyproof.Config)
	ka, hsb, err := keyproof.Assign(kc, p, pk, kw, eta)
	if err != nil {
		t.Fatal(err)
	}
	proof, _, err := keys.Prove(w.t.Key.Entry.Curve, w.t.Key.CS, w.t.Key.PK, ka)
	if err != nil {
		t.Fatal(err)
	}
	polys := [][]*big.Int{p.ToBig(pk.B), p.ToBig(pk.A)}
	hpk, err := hashes.DigPoly(hashes.BLS12381, evalc1.LabelHPk, append(polys[0], polys[1]...), w.t.QBits())
	if err != nil {
		t.Fatal(err)
	}
	hpkB := hashes.Bytes32(hpk)
	bv, err := PackPolys(w.t.QBits(), polys[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.board.Post(w.buyer, Item{Digest: hpkB, Label: LabelPiKey, Value: bv, Proof: proof}); err != nil {
		t.Fatal(err)
	}
	keyID, rcpt, err := w.market.RegisterKey(w.buyer, 0, hpkB, hashes.Bytes32(hsb))
	if err != nil || rcpt.Status != 1 {
		t.Fatalf("registerKey: %v", err)
	}
	b.keyIndex, b.sk, b.pk, b.keyW, b.eta, b.keyID = 0, sk, pk, kw, eta, keyID
	id, _, err := b.Order(s.OfferID, 1, []int64{1, -1}, 80)
	if err != nil {
		t.Fatal(err)
	}
	out, why, err := s.Handle(id)
	if err != nil || out != Rejected || !strings.Contains(why, "public coin") {
		t.Fatalf("expected a reject of a key off its public coin, got %v %s %v", out, why, err)
	}
}

// TestE7NonCanonical: a Case 1 buyer posts one coefficient v of its order
// ciphertext c0, or of its key b, as v + Q, which fits the QBits packing
// when v < 2^QBits - Q, with the recorded digest over the posted values and
// a valid pi_member or pi_key for the residues. The claim would digest the
// residues and revert on-chain while its blob published D, so the seller
// rejects the order before it computes: the escrow returns at once, and no
// claim is sent and no blob published.
func TestE7NonCanonical(t *testing.T) {
	w := newWorld(t, "case1_bfv")
	s := w.newSeller(t, 2, 32)
	sent := map[string]int{}
	s.Gas = func(tx string, _ *types.Receipt) { sent[tx]++ }
	balance := func() *big.Int { v, _ := w.env.BalanceAt(w.buyer.Addr); return v }
	expectReject := func(id *big.Int, what string) {
		t.Helper()
		before := balance()
		out, why, err := s.Handle(id)
		if err != nil || out != Rejected || !strings.Contains(why, "canonical") {
			t.Fatalf("%s: expected a reject, got %v %s %v", what, out, why, err)
		}
		if new(big.Int).Sub(balance(), before).Cmp(big.NewInt(1e15)) != 0 {
			t.Fatalf("%s: the reject did not return the escrow at once", what)
		}
		if sent["claimBlob"] != 0 || len(w.net.m) != 0 {
			t.Fatalf("%s: a claim was sent", what)
		}
		t.Logf("%s: %s", what, why)
	}
	expectReject(orderShifted(t, w, w.newBuyer(t), s.OfferID, 1), "ciphertext")
	b := registerShiftedKey(t, w, 1)
	id, _, err := b.Order(s.OfferID, 2, []int64{1, -1}, 80)
	if err != nil {
		t.Fatal(err)
	}
	expectReject(id, "key")
}

// shiftFilter returns a search for a coefficient of a polynomial below
// 2^QBits - Q (-1 if there is none). It estimates v/Q from the residues as
// frac(sum_j r_j y_j / q_j), y_j = (Q/q_j)^-1 mod q_j, and confirms a
// candidate exactly.
func shiftFilter(p *rlwe.Params, qBits int) func(q *rlwe.Params, a ring.Poly) int {
	qs := p.RingQ().ModuliChain()
	Q := p.Q()
	gap := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(qBits)), Q)
	bound, _ := new(big.Rat).SetFrac(gap, Q).Float64()
	ys := make([]uint64, len(qs))
	for j, qj := range qs {
		m := new(big.Int).SetUint64(qj)
		ys[j] = new(big.Int).ModInverse(new(big.Int).Mod(new(big.Int).Quo(Q, m), m), m).Uint64()
	}
	return func(q *rlwe.Params, a ring.Poly) int {
		for i := range a.Coeffs[0] {
			f := 0.0
			for j, qj := range qs {
				hi, lo := bits.Mul64(a.Coeffs[j][i], ys[j])
				_, r := bits.Div64(hi, lo, qj)
				f += float64(r) / float64(qj)
			}
			if f -= math.Floor(f); f < 2*bound && q.ToBig(a)[i].Cmp(gap) < 0 {
				return i
			}
		}
		return -1
	}
}

// grind calls try on every CPU, each with its own copy of the parameters,
// until a call succeeds, and returns its value: a buyer's search for
// randomness that leaves a coefficient below 2^QBits - Q, about
// 2^QBits / (N (2^QBits - Q)) tries (some 2^19 at N = 64, 2^12 at N = 8192).
func grind[T any](t *testing.T, w *world, try func(p *rlwe.Params) (T, bool)) T {
	t.Helper()
	var lit rlwe.ParamsLiteral
	for _, l := range rlwe.Flagship() {
		if l.Name == w.t.Name {
			lit = l
		}
	}
	res := make(chan T, 1)
	var stop atomic.Bool
	var wg sync.WaitGroup
	for k := 0; k < runtime.NumCPU(); k++ {
		p, err := registry.ParamsFor(lit, w.t.Scale, w.t.Class)
		if err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				if v, ok := try(p); ok {
					if stop.CompareAndSwap(false, true) {
						res <- v
					}
					return
				}
			}
		}()
	}
	wg.Wait()
	return <-res
}

// orderShifted places a Case 1 order of b whose posted c0 has a coefficient
// shifted by Q, with h_c over the posted values and pi_member for the
// residues; the buyer searches seeds of a' for a coefficient that the
// packing leaves room to shift.
func orderShifted(t *testing.T, w *world, b *Buyer, offerID *big.Int, slot uint16) *big.Int {
	t.Helper()
	tk, p := w.t, w.t.P
	wts := []int64{1, -1}
	o, err := w.market.OfferInfo(offerID)
	if err != nil {
		t.Fatal(err)
	}
	rhoF := make([]byte, hashes.SaltBytes)
	rand.Read(rhoF)
	comF, err := tk.Class.CommitF(tk.Field(), wts, rhoF)
	if err != nil {
		t.Fatal(err)
	}
	type found struct {
		seed [32]byte
		c    *rlwe.Ciphertext
		ew   *rlwe.EncWitness
		i    int
	}
	wh := valuation.EncodeForward(tk.Class.Expand(wts), p.N())
	shiftable := shiftFilter(p, tk.QBits())
	f := grind(t, w, func(q *rlwe.Params) (found, bool) {
		seed, a1, err := q.FreshSeededUniform(rand.Reader)
		if err != nil {
			return found{}, false
		}
		c, ew, err := q.EncryptSK(b.sk, wh, a1, rand.Reader)
		if err != nil {
			return found{}, false
		}
		i := shiftable(q, c.C0)
		return found{seed, c, ew, i}, i >= 0
	})
	cp := [][]*big.Int{p.ToBig(f.c.C0), p.ToBig(f.c.C1)}
	cp[0][f.i] = new(big.Int).Add(cp[0][f.i], p.Q())
	hc, err := hashes.DigPoly(hashes.BLS12381, evalc1.LabelHC, append(cp[0], cp[1]...), tk.QBits())
	if err != nil {
		t.Fatal(err)
	}
	ma, err := member.Assign(tk.Member.Entry.Config.(member.Config), p, f.c, wts, rhoF, b.sk.S, b.eta, f.ew)
	if err != nil {
		t.Fatal(err)
	}
	proof, _, err := keys.Prove(tk.Member.Entry.Curve, tk.Member.CS, tk.Member.PK, ma)
	if err != nil {
		t.Fatal(err)
	}
	v, err := PackWithSeed(tk.QBits(), f.seed, cp[0])
	if err != nil {
		t.Fatal(err)
	}
	hcB := hashes.Bytes32(hc)
	if _, err := w.board.Post(w.buyer, Item{Digest: hcB, Label: LabelPiMember, Value: v, Proof: proof}); err != nil {
		t.Fatal(err)
	}
	now, _ := w.env.BlockNumber()
	id, rcpt, err := w.market.Order(w.buyer, o.Price, offerID, slot, now+1+80, hashes.Bytes32(comF), hcB, b.keyID)
	if err != nil || rcpt.Status != 1 {
		t.Fatalf("order: %v", err)
	}
	return id
}

// registerShiftedKey registers a Case 1 key of the buyer whose posted b has
// a coefficient shifted by Q, with a on its public coin, h_pk over the
// posted values and pi_key for the residues; the buyer searches secrets for
// a coefficient that the packing leaves room to shift.
func registerShiftedKey(t *testing.T, w *world, index uint64) *Buyer {
	t.Helper()
	tk, p := w.t, w.t.P
	a, err := p.CoinPoly(hashes.Case1KeyCoin(w.buyer.Addr.Bytes(), index, hashes.LabelPkA))
	if err != nil {
		t.Fatal(err)
	}
	type found struct {
		sk *rlwe.SecretKey
		pk *rlwe.PublicKey
		kw *rlwe.KeyWitness
		i  int
	}
	shiftable := shiftFilter(p, tk.QBits())
	f := grind(t, w, func(q *rlwe.Params) (found, bool) {
		sk, pk, kw, err := q.KeyGen(a, rand.Reader)
		if err != nil {
			return found{}, false
		}
		i := shiftable(q, pk.B)
		return found{sk, pk, kw, i}, i >= 0
	})
	eta := make([]byte, hashes.SaltBytes)
	rand.Read(eta)
	ka, hsb, err := keyproof.Assign(tk.Key.Entry.Config.(keyproof.Config), p, f.pk, f.kw, eta)
	if err != nil {
		t.Fatal(err)
	}
	proof, _, err := keys.Prove(tk.Key.Entry.Curve, tk.Key.CS, tk.Key.PK, ka)
	if err != nil {
		t.Fatal(err)
	}
	polys := [][]*big.Int{p.ToBig(f.pk.B), p.ToBig(f.pk.A)}
	polys[0][f.i] = new(big.Int).Add(polys[0][f.i], p.Q())
	hpk, err := hashes.DigPoly(hashes.BLS12381, evalc1.LabelHPk, append(polys[0], polys[1]...), tk.QBits())
	if err != nil {
		t.Fatal(err)
	}
	hpkB := hashes.Bytes32(hpk)
	bv, err := PackPolys(tk.QBits(), polys[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.board.Post(w.buyer, Item{Digest: hpkB, Label: LabelPiKey, Value: bv, Proof: proof}); err != nil {
		t.Fatal(err)
	}
	keyID, rcpt, err := w.market.RegisterKey(w.buyer, index, hpkB, hashes.Bytes32(hsb))
	if err != nil || rcpt.Status != 1 {
		t.Fatalf("registerKey: %v", err)
	}
	b := NewBuyer(w.buyer, w.market, w.board, w.net, tk)
	b.keyIndex, b.sk, b.pk, b.keyW, b.eta, b.keyID = index, f.sk, f.pk, f.kw, eta, keyID
	return b
}

// TestE8ClaimSimulated: a claim that would revert is not sent. The market's
// verifier for the seller's claim key is that of another setup of the same
// set, so the claim passes every off-chain check and fails on-chain. The
// seller simulates it and rejects the order: the escrow returns at once, no
// claim is sent, so no blob (Case 1) or partial decryption (Case 2) is
// published, and the Case 2 slot keeps its unused key.
func TestE8ClaimSimulated(t *testing.T) {
	if testing.Short() {
		t.Skip("needs python with py-solc-x")
	}
	for _, params := range []string{"case1_bfv", "case2_bfv"} {
		w := deploy(t, toolkit(t, params), toolkit(t, params))
		s := w.newSeller(t, 1, 32)
		sent := map[string]int{}
		s.Gas = func(tx string, _ *types.Receipt) { sent[tx]++ }
		b := w.newBuyer(t)
		id, _, err := b.Order(s.OfferID, 1, []int64{1, 2}, 80)
		if err != nil {
			t.Fatal(err)
		}
		before, _ := w.env.BalanceAt(w.buyer.Addr)
		out, why, err := s.Handle(id)
		if err != nil || out != Rejected || !strings.Contains(why, "would revert") {
			t.Fatalf("%s: expected a reject, got %v %s %v", params, out, why, err)
		}
		after, _ := w.env.BalanceAt(w.buyer.Addr)
		if new(big.Int).Sub(after, before).Cmp(big.NewInt(1e15)) != 0 {
			t.Fatalf("%s: the reject did not return the escrow at once", params)
		}
		if sent["claimBlob"]+sent["claimDec"] != 0 || len(w.net.m) != 0 {
			t.Fatalf("%s: a claim was sent", params)
		}
		if w.t.Case() == rlwe.Case2 {
			si, _ := w.market.SlotInfo(s.OfferID, 1)
			if sl, ok := s.slots[1]; si.State != 0 || !ok || sl.Used() {
				t.Fatalf("%s: the slot did not stay usable", params)
			}
		}
		t.Logf("%s: %s", params, why)
	}
}
