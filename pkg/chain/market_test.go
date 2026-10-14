package chain_test

// Integration tests of FairExchangeMarket.sol on the simulated chain with
// reduced-size proofs, numbered as in docs/tests.md: D1-D9 (contract rules),
// B7 and B8 on chain (a claim proof is bound to its order and verified only
// under the key fixed at deployment), and F3-F6 for the Case 1 blob claim.
// They set up small verification keys on the fly and need python with
// py-solc-x; skipped with -short.

import (
	"crypto/rand"
	"math/big"
	"path/filepath"
	"testing"

	"fairhe/pkg/blob"
	"fairhe/pkg/chain"
	"fairhe/pkg/hashes"
	"fairhe/pkg/onchain"
	"fairhe/pkg/rlwe"
	"fairhe/pkg/valuation"
	"fairhe/pkg/zk/decproof"
	"fairhe/pkg/zk/evalc1"
	"fairhe/pkg/zk/keys"
	"fairhe/pkg/zk/registry"
	"fairhe/pkg/zk/valclass"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// Time bounds of the test offers, in blocks.
const tMin, tMax = 4, 7200

type setupKey struct {
	rec *keys.Record
	cs  constraint.ConstraintSystem
	pk  groth16.ProvingKey
	vk  groth16.VerifyingKey
	e   registry.Entry
}

func setupSmall(t *testing.T, circuit, params string) *setupKey {
	t.Helper()
	e, err := registry.Find(registry.Small, circuit, params)
	if err != nil {
		t.Fatal(err)
	}
	rec, cs, pk, vk, err := keys.Setup(e, t.TempDir(), registry.Small)
	if err != nil {
		t.Fatal(err)
	}
	return &setupKey{rec: rec, cs: cs, pk: pk, vk: vk, e: e}
}

func vkID(t *testing.T, k *setupKey) [32]byte {
	var id [32]byte
	copy(id[:], common.FromHex(k.rec.VKID))
	return id
}

func deployVerifier(t *testing.T, env *chain.Env, from *chain.Account, k *setupKey) common.Address {
	t.Helper()
	root, err := onchain.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	con, err := chain.LoadContract(filepath.Join(root, k.rec.VerifierArtifact))
	if err != nil {
		t.Fatal(err)
	}
	addr, _, err := env.Deploy(from, con)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func loadMarket(t *testing.T) *chain.Contract {
	t.Helper()
	root, err := onchain.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	con, err := chain.LoadContract(filepath.Join(root, "contracts", "out", "FairExchangeMarket.json"))
	if err != nil {
		t.Fatalf("%v (compile with: python scripts/compile_sol.py contracts/FairExchangeMarket.sol contracts/out/FairExchangeMarket.json FairExchangeMarket)", err)
	}
	return con
}

func prove(t *testing.T, k *setupKey, assignment frontend.Circuit) []byte {
	t.Helper()
	w, err := frontend.NewWitness(assignment, k.e.Curve.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(k.cs, k.pk, w, onchain.ProverOption())
	if err != nil {
		t.Fatal(err)
	}
	pb, err := onchain.ProofBytes(proof)
	if err != nil {
		t.Fatal(err)
	}
	return pb
}

func ok(t *testing.T, rcpt *types.Receipt, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	if rcpt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("%s reverted", what)
	}
}

func reverts(t *testing.T, rcpt *types.Receipt, err error, what string) {
	t.Helper()
	if err == nil && rcpt.Status == types.ReceiptStatusSuccessful {
		t.Fatalf("%s did not revert", what)
	}
}

func digest32(t *testing.T, d *big.Int, err error) [32]byte {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return hashes.Bytes32(d)
}

func balance(t *testing.T, env *chain.Env, a *chain.Account) *big.Int {
	t.Helper()
	b, err := env.BalanceAt(a.Addr)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func head(t *testing.T, env *chain.Env) uint64 {
	t.Helper()
	h, err := env.BlockNumber()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// mineTo advances the chain until its head is block n.
func mineTo(t *testing.T, env *chain.Env, n uint64) {
	t.Helper()
	if h := head(t, env); h < n {
		env.Mine(int(n - h))
	}
}

// c2World is a Case 2 market: the pi_dec verifier fixed at deployment, the
// off-chain VK IDs of pi_key and pi_enc, and one offer of q slots.
type c2World struct {
	env                                    *chain.Env
	m                                      *chain.Market
	dec, keyK, encK                        *setupKey
	p                                      *rlwe.Params
	cl                                     valclass.Class
	cfg                                    decproof.Config
	seller, buyer, buyer2, payout, relayer *chain.Account
	S                                      []int64
	comX                                   [32]byte
	slots                                  []*rlwe.Slot
	offerID, price                         *big.Int
}

func newC2World(t *testing.T, q uint16) *c2World {
	t.Helper()
	w := &c2World{
		dec:  setupSmall(t, registry.PiDec, "case2_bfv"),
		keyK: setupSmall(t, registry.PiKey, "case2_bfv"),
		encK: setupSmall(t, registry.PiEnc, "case2_bfv"),
	}
	w.p, w.cl = w.dec.e.RLWE, registry.ClassFor(rlwe.Case2BFV(), registry.Small)
	w.cfg, _ = decproof.ConfigFor(w.p)
	for _, a := range []**chain.Account{&w.seller, &w.buyer, &w.buyer2, &w.payout, &w.relayer} {
		*a, _ = chain.NewAccount()
	}
	env, err := chain.NewEnv(w.seller, w.buyer, w.buyer2, w.relayer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { env.Close() })
	w.env = env
	verifier := deployVerifier(t, env, w.seller, w.dec)
	w.m, _, err = chain.DeployMarket(env, w.seller, loadMarket(t),
		[][32]byte{vkID(t, w.dec)}, []common.Address{verifier}, [][32]byte{vkID(t, w.keyK), vkID(t, w.encK)})
	if err != nil {
		t.Fatal(err)
	}
	m := w.cl.M()
	w.S = make([]int64, m)
	for k := range w.S {
		w.S[k] = int64(1)<<20 + int64(97*k)
	}
	rho := make([]byte, hashes.SaltBytes)
	rand.Read(rho)
	comX, err := w.cl.CommitX(hashes.BN254, w.S, rho)
	w.comX = digest32(t, comX, err)
	sbar := make([]int64, w.p.N())
	for k, x := range w.S {
		sbar[m-1-k] = x
	}
	var hPk, hC1, hS [][32]byte
	qBits := new(big.Int).Sub(w.p.Q(), big.NewInt(1)).BitLen()
	for i := 1; i <= int(q); i++ {
		slot, err := w.p.PrepareSlot(w.seller.Addr.Bytes(), w.comX[:], uint64(i), sbar, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		w.slots = append(w.slots, slot)
		h, err := hashes.DigPoly(hashes.BN254, "h_pk", append(w.p.ToBig(slot.PK.B), w.p.ToBig(slot.PK.A)...), qBits)
		hPk = append(hPk, digest32(t, h, err))
		h, err = hashes.DigPoly(hashes.BN254, "h_c1", append(w.p.ToBig(slot.C1.C0), w.p.ToBig(slot.C1.C1)...), qBits)
		hC1 = append(hC1, digest32(t, h, err))
		hS = append(hS, hashes.Bytes32(slot.HS))
	}
	w.price = big.NewInt(1e15)
	var rcpt *types.Receipt
	w.offerID, rcpt, err = w.m.RegisterOffer(w.seller, w.args(q), hPk, hC1, hS)
	ok(t, rcpt, err, "registerOffer")
	t.Logf("registerOffer (Case 2, q = %d): %d gas", q, rcpt.GasUsed)
	return w
}

func (w *c2World) args(q uint16) chain.OfferArgs {
	return chain.OfferArgs{CaseId: 2, Payout: w.payout.Addr, ComX: w.comX, Price: w.price, TMin: tMin, TMax: tMax, Q: q,
		ClaimVk: vkID(nil, w.dec), KeyVk: vkID(nil, w.keyK), InputVk: vkID(nil, w.encK)}
}

// order lets from evaluate the weights on slot i and order it with refund
// time tRefDelta blocks after the block that includes the order.
func (w *c2World) order(t *testing.T, from *chain.Account, i uint16, tRefDelta uint64, wts []int64) (*big.Int, *rlwe.Ciphertext) {
	t.Helper()
	slot := w.slots[i-1]
	c2, _, err := w.p.EvalRerand(slot.PK, slot.C1, valuation.EncodeForward(w.cl.Expand(wts), w.p.N()), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hc, err := decproof.DigestC21(w.cfg, w.p.ToBig(c2.C1))
	id, rcpt, err := w.m.Order(from, w.price, w.offerID, i, head(t, w.env)+1+tRefDelta, [32]byte{byte(i)}, digest32(t, hc, err), [32]byte{})
	ok(t, rcpt, err, "order")
	return id, c2
}

// claim is the seller's partial decryption of an order on slot i with its
// pi_dec assignment and proof under the fixed key.
type claim struct {
	pd, efl *big.Int
	asg     *decproof.Circuit
	proof   []byte
}

func (w *c2World) claim(t *testing.T, orderID *big.Int, i uint16, c2 *rlwe.Ciphertext) *claim {
	t.Helper()
	slot := w.slots[i-1]
	pd, efl, err := slot.PartialDecryptOnce(w.p, c2.C1, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	asg, _, err := decproof.Assign(w.cfg, orderID, w.p.ToBig(c2.C1), slot.KeyWitness.S, slot.Eta, pd, efl)
	if err != nil {
		t.Fatal(err)
	}
	return &claim{pd: pd, efl: efl, asg: asg, proof: prove(t, w.dec, asg)}
}

// TestMarketRegistration: D8 (the budget: no more slots than q, one offer
// per data commitment) and B8 on chain (only verification keys fixed at
// deployment).
func TestMarketRegistration(t *testing.T) {
	if testing.Short() {
		t.Skip("needs python with py-solc-x")
	}
	w := newC2World(t, 4)
	digests := func(k int) [][32]byte {
		out := make([][32]byte, k)
		for i := range out {
			out[i][0] = byte(i + 1)
		}
		return out
	}
	fresh := w.args(4)
	fresh.ComX = [32]byte{0xc0, 0x11}
	// B8: a claim key or an off-chain key that the deployment did not fix.
	foreign := setupSmall(t, registry.PiDec, "case2_bfv")
	bad := fresh
	bad.ClaimVk = vkID(t, foreign)
	_, rcpt, err := w.m.RegisterOffer(w.seller, bad, digests(4), digests(4), digests(4))
	reverts(t, rcpt, err, "an offer with a claim key not fixed at deployment")
	bad = fresh
	bad.InputVk = vkID(t, foreign)
	_, rcpt, err = w.m.RegisterOffer(w.seller, bad, digests(4), digests(4), digests(4))
	reverts(t, rcpt, err, "an offer with an off-chain key not fixed at deployment")
	// D8: more slots than q, and Com(x) registered a second time (by the same
	// seller or by another account).
	_, rcpt, err = w.m.RegisterOffer(w.seller, fresh, digests(5), digests(5), digests(5))
	reverts(t, rcpt, err, "5 slots under q = 4")
	_, rcpt, err = w.m.RegisterOffer(w.seller, w.args(4), digests(4), digests(4), digests(4))
	reverts(t, rcpt, err, "a second offer for the same Com(x)")
	_, rcpt, err = w.m.RegisterOffer(w.buyer, w.args(2), digests(2), digests(2), digests(2))
	reverts(t, rcpt, err, "an offer for a registered Com(x) by another account")
	// Case 1 slots carry no keys.
	c1 := fresh
	c1.CaseId = 1
	_, rcpt, err = w.m.RegisterOffer(w.seller, c1, digests(4), digests(4), digests(4))
	reverts(t, rcpt, err, "a Case 1 offer with slot keys")
	// A fresh commitment with q slots is accepted.
	_, rcpt, err = w.m.RegisterOffer(w.seller, fresh, digests(4), digests(4), digests(4))
	ok(t, rcpt, err, "an offer for a fresh Com(x)")
}

// TestMarketCase2Rules runs the order, claim, refund, reject and retire
// rules of the contract (paper Section 4.2) on a Case 2 offer of q = 4 slots:
// D1-D7 and D9, with B7 and B8 for the claim proof.
func TestMarketCase2Rules(t *testing.T) {
	if testing.Short() {
		t.Skip("needs python with py-solc-x")
	}
	w := newC2World(t, 4)
	m, env, price := w.m, w.env, w.price
	wts := []int64{9, -17}
	none := [32]byte{}

	// D1: order rejects. T_ref is measured from the block that includes
	// the order, the next one.
	next := func() uint64 { return head(t, env) + 1 }
	rcpt, err := m.OrderRaw(w.buyer, new(big.Int).Sub(price, big.NewInt(1)), w.offerID, 1, next()+50, none, none, none)
	reverts(t, rcpt, err, "D1: order with a wrong price")
	rcpt, err = m.OrderRaw(w.buyer, price, w.offerID, 0, next()+50, none, none, none)
	reverts(t, rcpt, err, "D1: order on slot 0")
	rcpt, err = m.OrderRaw(w.buyer, price, w.offerID, 5, next()+50, none, none, none)
	reverts(t, rcpt, err, "D1: order on an unregistered slot")
	rcpt, err = m.OrderRaw(w.buyer, price, w.offerID, 1, next()+tMin-1, none, none, none)
	reverts(t, rcpt, err, "D1: T_ref - now below T_min")
	rcpt, err = m.OrderRaw(w.buyer, price, w.offerID, 1, next()+tMax+1, none, none, none)
	reverts(t, rcpt, err, "D1: T_ref - now above T_max")
	rcpt, err = m.OrderRaw(w.buyer, price, new(big.Int).Add(w.offerID, big.NewInt(1)), 1, next()+50, none, none, none)
	reverts(t, rcpt, err, "D1: order on an unregistered offer")

	idA, c2A := w.order(t, w.buyer, 1, 200, wts)
	idB, _ := w.order(t, w.buyer, 2, 200, []int64{3, 4})
	rcpt, err = m.OrderRaw(w.buyer2, price, w.offerID, 1, next()+200, none, none, none)
	reverts(t, rcpt, err, "D1: order on a slot with an open order")

	// D2, B7, B8: claims that fail.
	cA := w.claim(t, idA, 1, c2A)
	rcpt, err = m.ClaimDec(w.seller, idA, new(big.Int).Add(cA.pd, big.NewInt(1)), cA.proof, 1_000_000)
	reverts(t, rcpt, err, "D2: claim with a p that the proof does not open")
	rcpt, err = m.ClaimDec(w.seller, idB, cA.pd, cA.proof, 1_000_000)
	reverts(t, rcpt, err, "D2/B7: order A's claim for order B (another order ID and h_c21)")
	foreign := setupSmall(t, registry.PiDec, "case2_bfv")
	rcpt, err = m.ClaimDec(w.seller, idA, cA.pd, prove(t, foreign, cA.asg), 1_000_000)
	reverts(t, rcpt, err, "B8: claim proven under a key the deployment did not fix")

	// D3: a third party sends the seller's claim; the payout address is paid
	// and the sender only pays gas.
	pay0, rel0 := balance(t, env, w.payout), balance(t, env, w.relayer)
	rcpt, err = m.ClaimDec(w.relayer, idA, cA.pd, cA.proof, 0)
	ok(t, rcpt, err, "D3: claim sent by a third party")
	if d := new(big.Int).Sub(balance(t, env, w.payout), pay0); d.Cmp(price) != 0 {
		t.Fatalf("D3: payout received %s, want %s", d, price)
	}
	if d := new(big.Int).Sub(rel0, balance(t, env, w.relayer)); d.Cmp(chain.GasCost(rcpt)) != 0 {
		t.Fatalf("D3: the sender paid %s besides gas", new(big.Int).Sub(d, chain.GasCost(rcpt)))
	}
	ev, err := m.Event(rcpt, "Claimed")
	if err != nil || ev["p"].(*big.Int).Cmp(cA.pd) != 0 {
		t.Fatal("D3: the Claimed event does not carry p")
	}
	t.Logf("claimDec: %d gas", rcpt.GasUsed)
	f := w.p.DecodeBFV(w.p.Recover(c2A.C0, ev["p"].(*big.Int)), w.p.Q())
	if want := valuation.InnerProduct(w.cl.Expand(wts), w.S); f.Cmp(want) != 0 {
		t.Fatalf("decoded %s, want %s", f, want)
	}
	if si, _ := m.SlotInfo(w.offerID, 1); si.State != 1 {
		t.Fatal("D3: slot 1 not claimed")
	}
	rcpt, err = m.ClaimDec(w.seller, idA, cA.pd, cA.proof, 1_000_000)
	reverts(t, rcpt, err, "D8: a second claim of the slot")
	rcpt, err = m.Reject(w.seller, idA, 300_000)
	reverts(t, rcpt, err, "D5: reject after the claim")
	rcpt, err = m.OrderRaw(w.buyer2, price, w.offerID, 1, next()+50, none, none, none)
	reverts(t, rcpt, err, "D1: order on a claimed slot")

	// D5: reject of order B by the seller only; the escrow returns at once.
	rcpt, err = m.Reject(w.buyer, idB, 300_000)
	reverts(t, rcpt, err, "D5: reject by the buyer")
	buy0 := balance(t, env, w.buyer)
	rcpt, err = m.Reject(w.seller, idB, 0)
	ok(t, rcpt, err, "D5: reject")
	if d := new(big.Int).Sub(balance(t, env, w.buyer), buy0); d.Cmp(price) != 0 {
		t.Fatalf("D5: reject returned %s, want %s", d, price)
	}
	if st, _ := m.OrderState(idB); st != 4 {
		t.Fatalf("D5: order state %d after reject", st)
	}
	rcpt, err = m.ClaimDec(w.seller, idB, cA.pd, cA.proof, 1_000_000)
	reverts(t, rcpt, err, "D2: claim of an order that is not open")
	// D7: the rejected slot is ordered again and settled.
	idG, c2G := w.order(t, w.buyer2, 2, 200, wts)
	cG := w.claim(t, idG, 2, c2G)
	rcpt, err = m.ClaimDec(w.seller, idG, cG.pd, cG.proof, 0)
	ok(t, rcpt, err, "D7: claim of a re-order after a reject")

	// Slot 3: order C with a short refund time.
	idC, _ := w.order(t, w.buyer, 3, 10, wts)
	oiC, _ := m.OrderInfo(idC)
	rcpt, err = m.Refund(w.buyer, idC, 300_000)
	reverts(t, rcpt, err, "D4: refund before T_ref")
	rcpt, err = m.Retire(w.seller, w.offerID, 3, 300_000)
	reverts(t, rcpt, err, "D6: retire of a slot with an open order")
	mineTo(t, env, oiC.TRef)
	rcpt, err = m.Reject(w.seller, idC, 300_000)
	reverts(t, rcpt, err, "D5: reject after T_ref")
	// D7: past T_ref, before C's refund, the slot takes order D, settled by
	// a claim included at T_ref - 1 (D9).
	idD, c2D := w.order(t, w.buyer2, 3, 30, wts)
	oiD, _ := m.OrderInfo(idD)
	cD := w.claim(t, idD, 3, c2D)
	mineTo(t, env, oiD.TRef-2)
	rcpt, err = m.ClaimDec(w.seller, idD, cD.pd, cD.proof, 0)
	ok(t, rcpt, err, "D9: claim included at T_ref - 1")
	if rcpt.BlockNumber.Uint64() != oiD.TRef-1 {
		t.Fatalf("D9: claim included at %d, T_ref = %d", rcpt.BlockNumber, oiD.TRef)
	}
	// D7, D4: C's buyer is still refunded, once.
	buy0 = balance(t, env, w.buyer)
	rcpt, err = m.Refund(w.buyer, idC, 0)
	ok(t, rcpt, err, "D7: refund of the earlier order")
	if d := new(big.Int).Sub(balance(t, env, w.buyer), buy0); d.Cmp(new(big.Int).Sub(price, chain.GasCost(rcpt))) != 0 {
		t.Fatal("D4: refund did not return the price")
	}
	rcpt, err = m.Refund(w.buyer, idC, 300_000)
	reverts(t, rcpt, err, "D4: second refund")
	oiA, _ := m.OrderInfo(idA)
	mineTo(t, env, oiA.TRef)
	rcpt, err = m.Refund(w.buyer, idA, 300_000)
	reverts(t, rcpt, err, "D4: refund of a claimed order")

	// D9: order E; in block T_ref its claim fails and its refund succeeds.
	idE, c2E := w.order(t, w.buyer, 4, 12, wts)
	oiE, _ := m.OrderInfo(idE)
	cE := w.claim(t, idE, 4, c2E)
	mineTo(t, env, oiE.TRef-2)
	if err := m.Simulate(w.seller, "claimDec", idE, cE.pd, cE.proof); err != nil {
		t.Fatalf("D9: the claim fails before T_ref: %v", err)
	}
	mineTo(t, env, oiE.TRef-1)
	txC, _ := m.Tx(w.seller, nil, 1_000_000, 2, "claimDec", idE, cE.pd, cE.proof)
	txR, _ := m.Tx(w.buyer, nil, 300_000, 1, "refund", idE)
	rs, err := env.SendInOneBlock([]chain.TxSpec{txC, txR})
	if err != nil {
		t.Fatal(err)
	}
	if rs[0].BlockNumber.Uint64() != oiE.TRef || rs[1].BlockNumber.Uint64() != oiE.TRef || rs[0].TransactionIndex > rs[1].TransactionIndex {
		t.Fatalf("D9: claim at %d (index %d), refund at %d (index %d), T_ref = %d",
			rs[0].BlockNumber, rs[0].TransactionIndex, rs[1].BlockNumber, rs[1].TransactionIndex, oiE.TRef)
	}
	if rs[0].Status != types.ReceiptStatusFailed || rs[1].Status != types.ReceiptStatusSuccessful {
		t.Fatalf("D9: in block T_ref the claim has status %d and the refund %d", rs[0].Status, rs[1].Status)
	}
	// D6: without an open order the slot can be retired, and then takes no
	// order.
	rcpt, err = m.Retire(w.seller, w.offerID, 4, 0)
	ok(t, rcpt, err, "D6: retire")
	rcpt, err = m.OrderRaw(w.buyer, price, w.offerID, 4, next()+50, none, none, none)
	reverts(t, rcpt, err, "D6: order on a retired slot")
}

// TestMarketCase1 runs Case 1 on the contract: the buyer's key and orders,
// the blob-carrying claim with pi_eval, and the buyer's decryption of the
// deliverable read from the blob. F3-F6 for the blob, D2 for the blob
// checks, D3 and B7 for the claim.
func TestMarketCase1(t *testing.T) {
	if testing.Short() {
		t.Skip("needs python with py-solc-x")
	}
	ev1 := setupSmall(t, registry.PiEvalC1, "case1_bfv")
	keyK := setupSmall(t, registry.PiKey, "case1_bfv")
	memK := setupSmall(t, registry.PiMember, "case1_bfv")
	p, cl := ev1.e.RLWE, *ev1.e.Class
	cfg := ev1.e.Config.(evalc1.Config)

	seller, _ := chain.NewAccount()
	buyer, _ := chain.NewAccount()
	payout, _ := chain.NewAccount()
	relayer, _ := chain.NewAccount()
	env, err := chain.NewEnv(seller, buyer, relayer)
	if err != nil {
		t.Fatal(err)
	}
	defer env.Close()
	verifier := deployVerifier(t, env, seller, ev1)
	market, _, err := chain.DeployMarket(env, seller, loadMarket(t),
		[][32]byte{vkID(t, ev1)}, []common.Address{verifier}, [][32]byte{vkID(t, keyK), vkID(t, memK)})
	if err != nil {
		t.Fatal(err)
	}

	// Buyer registration: key from public coins, digests h_pk and h_sB.
	a, _ := p.CoinPoly(hashes.Case1KeyCoin(buyer.Addr.Bytes(), 0, hashes.LabelPkA))
	sk, pk, _, err := p.KeyGen(a, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	etaB := make([]byte, hashes.SaltBytes)
	rand.Read(etaB)
	hsb, err := hashes.DigSecret(hashes.BLS12381, "h_sB", sk.S, etaB)
	hsbB := digest32(t, hsb, err)
	// Seller registration: two slots.
	m := cl.M()
	S := make([]int64, m)
	for k := range S {
		S[k] = int64(1)<<21 + int64(31*k)
	}
	rho := make([]byte, hashes.SaltBytes)
	rand.Read(rho)
	comX, err := cl.CommitX(hashes.BLS12381, S, rho)
	comXB := digest32(t, comX, err)
	price := big.NewInt(2e15)
	offerID, rcpt, err := market.RegisterOffer(seller, chain.OfferArgs{
		CaseId: 1, Payout: payout.Addr, ComX: comXB, Price: price, TMin: tMin, TMax: tMax, Q: 2,
		ClaimVk: vkID(t, ev1), KeyVk: vkID(t, keyK), InputVk: vkID(t, memK),
	}, nil, nil, nil)
	ok(t, rcpt, err, "registerOffer")
	// Buyer: encrypt w_hat, register the key, order slots 1 and 2.
	w := []int64{-5, 11}
	a1, _ := p.FreshUniform(rand.Reader)
	c, _, err := p.EncryptSK(sk, cl.Expand(w), a1, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hc, hpk, err := evalc1.PublicDigests(cfg, p, c, pk)
	if err != nil {
		t.Fatal(err)
	}
	keyID, rcpt, err := market.RegisterKey(buyer, 0, hashes.Bytes32(hpk), hsbB)
	ok(t, rcpt, err, "registerKey")
	t.Logf("registerKey: %d gas", rcpt.GasUsed)
	_, rcpt, err = market.RegisterKey(buyer, 0, hashes.Bytes32(hpk), hsbB)
	reverts(t, rcpt, err, "a second key under the same index")
	orderID, rcpt, err := market.Order(buyer, price, offerID, 1, head(t, env)+31, [32]byte{7}, hashes.Bytes32(hc), keyID)
	ok(t, rcpt, err, "order")
	order2, rcpt, err := market.Order(buyer, price, offerID, 2, head(t, env)+31, [32]byte{7}, hashes.Bytes32(hc), keyID)
	ok(t, rcpt, err, "second order")

	// Seller: evaluate, sanitise, switch; blob link; pi_eval.
	sbar := make([]int64, p.N())
	for k, x := range S {
		sbar[m-1-k] = x
	}
	prod, err := p.MulPlain(c, sbar)
	if err != nil {
		t.Fatal(err)
	}
	san, sw, err := p.Sanitize(pk, prod, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	D, xw, err := p.ExtractSwitch(san)
	if err != nil {
		t.Fatal(err)
	}
	elems, err := evalc1.BlobElements(cfg, D)
	if err != nil {
		t.Fatal(err)
	}
	hD, err := hashes.Dig(hashes.BLS12381, evalc1.LabelHD, elems)
	if err != nil {
		t.Fatal(err)
	}
	link, err := blob.NewLink(elems, hashes.Bytes32(hD))
	if err != nil {
		t.Fatal(err)
	}
	asg, pub, err := evalc1.Assign(cfg, &evalc1.Inputs{Params: p, OrderID: orderID, PK: pk, C: c, X: S, Rho: rho,
		San: sw, Del: D, Sw: xw, Z: link.Z})
	if err != nil {
		t.Fatal(err)
	}
	if pub.YZ.Cmp(link.Y) != 0 {
		t.Fatal("F2: circuit value at z differs from the KZG claim")
	}
	proof := prove(t, ev1, asg)
	sc, err := link.Sidecar()
	if err != nil {
		t.Fatal(err)
	}
	com, kp := chain.KZGBytes(link.Commitment, link.Proof)
	claim := chain.BlobClaim{HD: hashes.Bytes32(hD), YZ: link.Y, Commitment: com, KzgProof: kp}

	// D2: the blob checks. Another blob (a commitment and opening of its own)
	// to supply wrong values.
	other := append([]*big.Int(nil), elems...)
	other[0] = new(big.Int).Add(other[0], big.NewInt(1))
	otherLink, err := blob.NewLink(other, hashes.Bytes32(hD))
	if err != nil {
		t.Fatal(err)
	}
	oCom, oKp := chain.KZGBytes(otherLink.Commitment, otherLink.Proof)
	rcpt, err = market.ClaimBlobNoBlob(seller, orderID, claim, proof)
	reverts(t, rcpt, err, "D2: claim without a blob (blobhash(0) = 0)")
	bad := claim
	bad.YZ = new(big.Int).Add(link.Y, big.NewInt(1))
	rcpt, err = market.ClaimBlob(seller, orderID, bad, proof, sc, 3_000_000)
	reverts(t, rcpt, err, "D2: claim with a wrong y_z")
	bad = claim
	bad.Commitment = oCom
	rcpt, err = market.ClaimBlob(seller, orderID, bad, proof, sc, 3_000_000)
	reverts(t, rcpt, err, "D2: claim with another blob's commitment")
	bad = claim
	bad.KzgProof = oKp
	rcpt, err = market.ClaimBlob(seller, orderID, bad, proof, sc, 3_000_000)
	reverts(t, rcpt, err, "D2: claim with a wrong opening proof")
	// F4: a blob that differs from D in one coefficient, with a valid
	// opening of its own at its z, fails pi_eval.
	D2 := &rlwe.Deliverable{D0: D.D0, D1: append([]*big.Int(nil), D.D1...)}
	D2.D1[5] = new(big.Int).Add(D.D1[5], big.NewInt(1))
	D2.D1[5].Mod(D2.D1[5], p.QDel())
	elems2, err := evalc1.BlobElements(cfg, D2)
	if err != nil {
		t.Fatal(err)
	}
	link2, err := blob.NewLink(elems2, hashes.Bytes32(hD))
	if err != nil {
		t.Fatal(err)
	}
	sc2, err := link2.Sidecar()
	if err != nil {
		t.Fatal(err)
	}
	com2, kp2 := chain.KZGBytes(link2.Commitment, link2.Proof)
	rcpt, err = market.ClaimBlob(seller, orderID, chain.BlobClaim{HD: hashes.Bytes32(hD), YZ: link2.Y, Commitment: com2, KzgProof: kp2}, proof, sc2, 3_000_000)
	reverts(t, rcpt, err, "F4: claim whose blob differs from D in one coefficient")
	// B7: the claim of order 1 does not settle order 2.
	rcpt, err = market.ClaimBlob(seller, order2, claim, proof, sc, 3_000_000)
	reverts(t, rcpt, err, "B7: order 1's claim for order 2")

	// D3, F5: a third party sends the type-3 claim; the payout address is paid.
	pay0 := balance(t, env, payout)
	rcpt, err = market.ClaimBlob(relayer, orderID, claim, proof, sc, 3_000_000)
	ok(t, rcpt, err, "F5/D3: claimBlob sent by a third party")
	if d := new(big.Int).Sub(balance(t, env, payout), pay0); d.Cmp(price) != 0 {
		t.Fatalf("D3: payout received %s, want %s", d, price)
	}
	t.Logf("claimBlob: %d gas, blob gas %d", rcpt.GasUsed, rcpt.BlobGasUsed)
	ev, err := market.Event(rcpt, "Claimed")
	if err != nil {
		t.Fatal(err)
	}
	// F3: the contract's blobhash(0) is the versioned hash computed off chain.
	vh := ev["versionedHash"].([32]byte)
	if vh != link.VH || ev["hD"].([32]byte) != hashes.Bytes32(hD) {
		t.Fatal("F3: the Claimed event's versioned hash or h_D differs from the seller's")
	}
	// F6: the buyer reads D from the kept sidecar before T_ref and decrypts.
	got, err := blob.Retrieve(sc, vh, len(elems))
	if err != nil {
		t.Fatal(err)
	}
	coeffs, err := blob.Unpack(got, cfg.DBits, cfg.DPer, p.N()+1)
	if err != nil {
		t.Fatal(err)
	}
	f := p.DecodeDeliverableBFV(sk, &rlwe.Deliverable{D0: coeffs[0], D1: coeffs[1:]})
	want := valuation.InnerProduct(cl.Expand(w), S)
	if f.Cmp(want) != 0 {
		t.Fatalf("F6: decoded %s, want %s", f, want)
	}
}
