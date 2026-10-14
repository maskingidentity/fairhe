package market

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"fairhe/pkg/blob"
	"fairhe/pkg/chain"
	"fairhe/pkg/clock"
	"fairhe/pkg/hashes"
	"fairhe/pkg/onchain"
	"fairhe/pkg/rlwe"
	"fairhe/pkg/zk/decproof"
	"fairhe/pkg/zk/encproof"
	"fairhe/pkg/zk/evalc1"
	"fairhe/pkg/zk/evalc2"
	"fairhe/pkg/zk/keyproof"
	"fairhe/pkg/zk/keys"
	"fairhe/pkg/zk/member"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// DA labels of the off-chain proofs and of the slot values.
const (
	LabelPiKey    = "pi_key"
	LabelPiEnc    = "pi_enc"
	LabelPiMember = "pi_member"
	LabelPiEval   = "pi_eval"
	LabelHPk      = "h_pk"
	LabelHC1      = "h_c1"
)

// Outcome is what the seller did with an order.
type Outcome int

const (
	// Claimed: the claim was accepted and paid.
	Claimed Outcome = iota
	// Rejected: the seller returned the escrow (failed proofs, missing data,
	// or too little time before the refund time).
	Rejected
	// Retired: the claim was sent but not accepted; the slot is retired.
	Retired
	// Skipped: the order was not open.
	Skipped
)

func (o Outcome) String() string {
	return [...]string{"claimed", "rejected", "retired", "skipped"}[o]
}

// Seller is the seller's state machine: it registers its data commitment and
// slots (Case 2 slots prepared in advance with their proofs on the board),
// checks each order's proofs against the values it fetches by their recorded
// digests (pi_key once per buyer key), computes and proves, and claims only
// while more than delta blocks remain before the refund time, checked again
// after proving; otherwise it rejects, and a Case 2 slot whose partial
// decryption was never sent stays usable. It retires a slot whose claim was
// broadcast but not accepted, so that a session key never answers twice, and
// erases a slot's secret once the slot is claimed or retired.
type Seller struct {
	Acct   *chain.Account
	Payout common.Address
	M      *chain.Market
	Board  Board
	Net    *BlobNet
	T      *Toolkit
	Delta  uint64

	S        []int64
	rho      []byte
	comX     *big.Int
	OfferID  *big.Int
	slots    map[uint16]*rlwe.Slot
	keysSeen map[[32]byte]*rlwe.PublicKey // buyer keys whose digest, public coin and pi_key passed

	// Trace, when set, receives the duration of each stage of Register and
	// Handle, and Gas the receipt of each transaction. AfterProve, when set,
	// runs between proving and the deadline check before the claim (tests
	// use it to let blocks pass while the seller proves).
	Trace      func(stage string, d time.Duration)
	Gas        func(tx string, rcpt *types.Receipt)
	AfterProve func()
}

func (s *Seller) mark(stage string, start clock.Reading) clock.Reading {
	if s.Trace != nil {
		s.Trace(stage, clock.Since(start))
	}
	return clock.Now()
}

func (s *Seller) gas(tx string, rcpt *types.Receipt) {
	if s.Gas != nil && rcpt != nil {
		s.Gas(tx, rcpt)
	}
}

// NewSeller commits to the data S; board carries the bulky values and net
// retains the blobs of its claims.
func NewSeller(acct *chain.Account, payout common.Address, m *chain.Market, board Board, net *BlobNet, t *Toolkit, S []int64, delta uint64) (*Seller, error) {
	rho := make([]byte, hashes.SaltBytes)
	if _, err := rand.Read(rho); err != nil {
		return nil, err
	}
	comX, err := t.Class.CommitX(t.Field(), S, rho)
	if err != nil {
		return nil, err
	}
	return &Seller{Acct: acct, Payout: payout, M: m, Board: board, Net: net, T: t, Delta: delta, S: S, rho: rho, comX: comX,
		slots: map[uint16]*rlwe.Slot{}, keysSeen: map[[32]byte]*rlwe.PublicKey{}}, nil
}

// ComX returns the registered Com(x).
func (s *Seller) ComX() [32]byte { return hashes.Bytes32(s.comX) }

func (s *Seller) sbar() []int64 {
	m := s.T.Class.M()
	out := make([]int64, s.T.P.N())
	for k, x := range s.S {
		out[m-1-k] = x
	}
	return out
}

// Register posts the offer with q slots. In Case 2 every slot gets its
// session key and data ciphertext from public coins, posted on the board
// with pi_key and pi_enc under the slot's digests before the offer is
// registered. T_min must exceed delta: it covers fetching and checking an
// order, computing and proving, plus delta (paper Section 4.1).
func (s *Seller) Register(q uint16, price *big.Int, tMin, tMax uint64) (*types.Receipt, error) {
	if tMin <= s.Delta {
		return nil, fmt.Errorf("market: T_min = %d blocks does not exceed delta = %d", tMin, s.Delta)
	}
	t := s.T
	args := chain.OfferArgs{
		CaseId: uint8(t.Case()), Payout: s.Payout, ComX: s.ComX(), Price: price, TMin: tMin, TMax: tMax, Q: q,
		Terms: t.Terms(), KeyVk: t.Key.VKID(),
	}
	var hPk, hC1, hS [][32]byte
	start := clock.Now()
	if t.Case() == rlwe.Case1 {
		args.ClaimVk, args.InputVk = t.EvalC1.VKID(), t.Member.VKID()
		start = s.mark("seller.prepare_slots", start)
	} else {
		args.ClaimVk, args.InputVk = t.Dec.VKID(), t.Enc.VKID()
		comX := s.ComX()
		var items []Item
		for i := uint16(1); i <= q; i++ {
			slot, err := t.P.PrepareSlot(s.Acct.Addr.Bytes(), comX[:], uint64(i), s.sbar(), rand.Reader)
			if err != nil {
				return nil, err
			}
			s.slots[i] = slot
			hp, hc, its, err := s.slotItems(slot)
			if err != nil {
				return nil, err
			}
			items = append(items, its...)
			hPk, hC1, hS = append(hPk, hp), append(hC1, hc), append(hS, hashes.Bytes32(slot.HS))
		}
		start = s.mark("seller.prepare_slots", start)
		rcpts, err := s.Board.Post(s.Acct, items...)
		for _, r := range rcpts {
			s.gas("post_slots", r)
		}
		if err != nil {
			return nil, err
		}
		start = s.mark("seller.post_slots", start)
	}
	id, rcpt, err := s.M.RegisterOffer(s.Acct, args, hPk, hC1, hS)
	s.gas("registerOffer", rcpt)
	if err != nil {
		return rcpt, err
	}
	s.mark("seller.register_tx", start)
	s.OfferID = id
	return rcpt, nil
}

// slotItems proves a slot's pi_key and pi_enc and returns the digests the
// ledger records with the board items of the slot. The digests cover the
// whole key and ciphertext, but the items carry only b and c1,0: a and c1,1
// are public coins that the buyer recomputes (option O5).
func (s *Seller) slotItems(slot *rlwe.Slot) (hPk, hC1 [32]byte, items []Item, err error) {
	t, p := s.T, s.T.P
	pkPolys := [][]*big.Int{p.ToBig(slot.PK.B), p.ToBig(slot.PK.A)}
	c1Polys := [][]*big.Int{p.ToBig(slot.C1.C0), p.ToBig(slot.C1.C1)}
	hp, err := hashes.DigPoly(hashes.BN254, LabelHPk, append(pkPolys[0], pkPolys[1]...), t.QBits())
	if err != nil {
		return
	}
	hc, err := hashes.DigPoly(hashes.BN254, LabelHC1, append(c1Polys[0], c1Polys[1]...), t.QBits())
	if err != nil {
		return
	}
	hPk, hC1 = hashes.Bytes32(hp), hashes.Bytes32(hc)
	bv, err := PackPolys(t.QBits(), pkPolys[0])
	if err != nil {
		return
	}
	cv, err := PackPolys(t.QBits(), c1Polys[0])
	if err != nil {
		return
	}
	kc := t.Key.Entry.Config.(keyproof.Config)
	ka, _, err := keyproof.Assign(kc, p, slot.PK, slot.KeyWitness, slot.Eta)
	if err != nil {
		return
	}
	kp, _, err := keys.Prove(t.Key.Entry.Curve, t.Key.CS, t.Key.PK, ka)
	if err != nil {
		return
	}
	ec := t.Enc.Entry.Config.(encproof.Config)
	ea, err := encproof.Assign(ec, p, slot.C1, s.S, s.rho, slot.KeyWitness.S, slot.Eta, slot.EncWitness)
	if err != nil {
		return
	}
	ep, _, err := keys.Prove(t.Enc.Entry.Curve, t.Enc.CS, t.Enc.PK, ea)
	if err != nil {
		return
	}
	items = []Item{{Digest: hPk, Label: LabelPiKey, Value: bv, Proof: kp}, {Digest: hC1, Label: LabelPiEnc, Value: cv, Proof: ep}}
	return hPk, hC1, items, nil
}

// publishSlot posts one slot's items on the board and returns its digests.
func (s *Seller) publishSlot(slot *rlwe.Slot) (hPk, hC1 [32]byte, err error) {
	hPk, hC1, items, err := s.slotItems(slot)
	if err != nil {
		return
	}
	_, err = s.Board.Post(s.Acct, items...)
	return hPk, hC1, err
}

// Handle processes one order and returns what the seller did and why.
func (s *Seller) Handle(orderID *big.Int) (Outcome, string, error) {
	oi, err := s.M.OrderInfo(orderID)
	if err != nil {
		return Skipped, "", err
	}
	if oi.State != 1 {
		return Skipped, "order not open", nil
	}
	if out, why, done, err := s.deadline(orderID, oi); done {
		return out, why, err
	}
	if s.T.Case() == rlwe.Case1 {
		return s.handleCase1(orderID, oi)
	}
	return s.handleCase2(orderID, oi)
}

// deadline applies the claim deadline: with at most delta blocks left before
// the refund time the seller does not claim and rejects the order (done is
// true); once the refund time has passed the order is no longer open and the
// buyer refunds.
func (s *Seller) deadline(orderID *big.Int, oi *chain.OrderInfo) (Outcome, string, bool, error) {
	now, err := s.M.Env.BlockNumber()
	if err != nil {
		return Skipped, "", true, err
	}
	if now >= oi.TRef {
		return Skipped, "refund time passed", true, nil
	}
	if now+s.Delta >= oi.TRef {
		out, why, err := s.reject(orderID, "at most delta blocks before the refund time")
		return out, why, true, err
	}
	return Claimed, "", false, nil
}

func (s *Seller) reject(orderID *big.Int, why string) (Outcome, string, error) {
	rcpt, err := s.M.Reject(s.Acct, orderID, 0)
	s.gas("reject", rcpt)
	if err != nil {
		return Rejected, why, err
	}
	if rcpt.Status != types.ReceiptStatusSuccessful {
		return Rejected, why, errors.New("market: reject reverted")
	}
	return Rejected, why, nil
}

// retire marks a slot unusable and erases its session secret.
func (s *Seller) retire(slot uint16, why string) (Outcome, string, error) {
	rcpt, err := s.M.Retire(s.Acct, s.OfferID, slot, 0)
	s.gas("retire", rcpt)
	if err != nil {
		return Retired, why, err
	}
	if rcpt.Status != types.ReceiptStatusSuccessful {
		return Retired, why, errors.New("market: retire reverted")
	}
	s.erase(slot)
	return Retired, why, nil
}

// erase drops a Case 2 slot's session secret once the slot is claimed or
// retired.
func (s *Seller) erase(slot uint16) {
	if sl, ok := s.slots[slot]; ok {
		sl.Erase()
		delete(s.slots, slot)
	}
}

// beforeClaim runs after proving: the deadline again, since computing and
// proving took time. A Case 2 partial decryption that is not sent is
// withdrawn, so the slot may serve another order.
func (s *Seller) beforeClaim(orderID *big.Int, oi *chain.OrderInfo, slot *rlwe.Slot) (Outcome, string, bool, error) {
	if s.AfterProve != nil {
		s.AfterProve()
	}
	out, why, done, err := s.deadline(orderID, oi)
	if done && slot != nil {
		slot.Withdraw()
	}
	return out, why, done, err
}

// claimFailed handles a claim that was broadcast but not accepted: if a copy
// of it was included first the order is claimed and paid to the payout
// address; otherwise the claim exposed D (and in Case 2 used the session
// key), so the seller rejects the order if it is still open and retires the
// slot.
func (s *Seller) claimFailed(orderID *big.Int, oi *chain.OrderInfo, cause error) (Outcome, string, error) {
	st, err := s.M.OrderState(orderID)
	if err != nil {
		return Skipped, "", err
	}
	if st == 2 {
		s.erase(oi.Slot)
		return Claimed, "claimed by a copy of the claim", nil
	}
	why := fmt.Sprintf("claim not accepted (%v)", cause)
	now, err := s.M.Env.BlockNumber()
	if err != nil {
		return Skipped, "", err
	}
	if st == 1 && now < oi.TRef {
		if _, _, err := s.reject(orderID, why); err != nil {
			return Rejected, why, err
		}
	}
	return s.retire(oi.Slot, why)
}

func (s *Seller) handleCase1(orderID *big.Int, oi *chain.OrderInfo) (Outcome, string, error) {
	t, p := s.T, s.T.P
	start := clock.Now()
	keyID, err := s.M.OrderKeyID(orderID)
	if err != nil {
		return Skipped, "", err
	}
	owner, keyIndex, hPk, hSB, err := s.M.BuyerKey(keyID)
	if err != nil {
		return Skipped, "", err
	}
	// The buyer's key, once per registered key: b fetched by the digest,
	// a recomputed from the public coin, the digest over (b, a), pi_key.
	pk := s.keysSeen[keyID]
	if pk == nil {
		raw, kp, err := s.Board.Fetch(owner, hPk, LabelPiKey)
		if err != nil {
			return s.reject(orderID, "buyer key: "+err.Error())
		}
		polys, err := UnpackPolys(raw, t.QBits(), p.N(), 1)
		if err != nil {
			return s.reject(orderID, "malformed buyer key")
		}
		coin, err := p.CoinPoly(hashes.Case1KeyCoin(owner.Bytes(), keyIndex, hashes.LabelPkA))
		if err != nil {
			return Skipped, "", err
		}
		if h, err := hashes.DigPoly(hashes.BLS12381, evalc1.LabelHPk, append(polys[0], p.ToBig(coin)...), t.QBits()); err != nil || hashes.Bytes32(h) != hPk {
			return s.reject(orderID, "buyer key does not match its digest with a on its public coin")
		}
		pk = &rlwe.PublicKey{B: p.FromBig(polys[0]), A: coin}
		kc := t.Key.Entry.Config.(keyproof.Config)
		if keys.VerifyOffchain(t.Key.Entry.Curve, t.Key.VK, keyproof.PublicAssignment(kc, p, pk, new(big.Int).SetBytes(hSB[:])), kp) != nil {
			return s.reject(orderID, "pi_key fails")
		}
		s.keysSeen[keyID] = pk
	}
	// The ordered ciphertext (c0 and the seed of a') and pi_member.
	raw, mp, err := s.Board.Fetch(oi.Buyer, oi.HInput, LabelPiMember)
	if err != nil {
		return s.reject(orderID, "ciphertext: "+err.Error())
	}
	cp, seed, err := UnpackWithSeed(raw, t.QBits(), p.N(), 1)
	if err != nil {
		return s.reject(orderID, "malformed ciphertext")
	}
	a1, err := p.SeededUniform(seed)
	if err != nil {
		return Skipped, "", err
	}
	if h, err := hashes.DigPoly(hashes.BLS12381, evalc1.LabelHC, append(cp[0], p.ToBig(a1)...), t.QBits()); err != nil || hashes.Bytes32(h) != oi.HInput {
		return s.reject(orderID, "ciphertext does not match its digest")
	}
	c := &rlwe.Ciphertext{C0: p.FromBig(cp[0]), C1: a1}
	mc := t.Member.Entry.Config.(member.Config)
	pub := member.PublicAssignment(mc, p, c, new(big.Int).SetBytes(oi.ComF[:]), new(big.Int).SetBytes(hSB[:]))
	if keys.VerifyOffchain(t.Member.Entry.Curve, t.Member.VK, pub, mp) != nil {
		return s.reject(orderID, "pi_member fails")
	}
	start = s.mark("seller.check_order", start)
	// Evaluate, sanitise, extract and switch; link the blob; prove; claim.
	prod, err := p.MulPlain(c, s.sbar())
	if err != nil {
		return Skipped, "", err
	}
	san, sw, err := p.Sanitize(pk, prod, rand.Reader)
	if err != nil {
		return Skipped, "", err
	}
	D, xw, err := p.ExtractSwitch(san)
	if err != nil {
		return Skipped, "", err
	}
	cfg := t.EvalC1.Entry.Config.(evalc1.Config)
	elems, err := evalc1.BlobElements(cfg, D)
	if err != nil {
		return Skipped, "", err
	}
	hD, err := hashes.Dig(hashes.BLS12381, evalc1.LabelHD, elems)
	if err != nil {
		return Skipped, "", err
	}
	link, err := blob.NewLink(elems, hashes.Bytes32(hD))
	if err != nil {
		return Skipped, "", err
	}
	start = s.mark("seller.he_and_blob", start)
	asg, _, err := evalc1.Assign(cfg, &evalc1.Inputs{Params: p, OrderID: orderID, PK: pk, C: c, X: s.S, Rho: s.rho,
		San: sw, Del: D, Sw: xw, Z: link.Z})
	if err != nil {
		return Skipped, "", err
	}
	_, proof, err := keys.Prove(t.EvalC1.Entry.Curve, t.EvalC1.CS, t.EvalC1.PK, asg, onchain.ProverOption())
	if err != nil {
		return Skipped, "", err
	}
	pb, err := onchain.ProofBytes(proof)
	if err != nil {
		return Skipped, "", err
	}
	sc, err := link.Sidecar()
	if err != nil {
		return Skipped, "", err
	}
	start = s.mark("seller.prove", start)
	if out, why, done, err := s.beforeClaim(orderID, oi, nil); done {
		return out, why, err
	}
	start = clock.Now()
	com, kzp := chain.KZGBytes(link.Commitment, link.Proof)
	rcpt, err := s.M.ClaimBlob(s.Acct, orderID, chain.BlobClaim{HD: hashes.Bytes32(hD), YZ: link.Y, Commitment: com, KzgProof: kzp}, pb, sc, 3_000_000)
	if rcpt != nil { // included, even if reverted: the network keeps the blob
		s.Net.Publish(sc, rcpt.BlockNumber.Uint64())
	}
	s.gas("claimBlob", rcpt)
	s.mark("seller.claim_tx", start)
	if err == nil && rcpt.Status != types.ReceiptStatusSuccessful {
		err = errors.New("claim reverted")
	}
	if err != nil {
		return s.claimFailed(orderID, oi, err)
	}
	return Claimed, "", nil
}

func (s *Seller) handleCase2(orderID *big.Int, oi *chain.OrderInfo) (Outcome, string, error) {
	t, p := s.T, s.T.P
	start := clock.Now()
	slot, ok := s.slots[oi.Slot]
	if !ok {
		return s.reject(orderID, "unknown slot")
	}
	raw, ep, err := s.Board.Fetch(oi.Buyer, oi.HInput, LabelPiEval)
	if err != nil {
		return s.reject(orderID, "c2,1: "+err.Error())
	}
	cp, err := UnpackPolys(raw, t.QBits(), p.N(), 1)
	if err != nil {
		return s.reject(orderID, "malformed c2,1")
	}
	dc := t.Dec.Entry.Config.(decproof.Config)
	if h, err := decproof.DigestC21(dc, cp[0]); err != nil || hashes.Bytes32(h) != oi.HInput {
		return s.reject(orderID, "c2,1 does not match its digest")
	}
	ec := t.EvalC2.Entry.Config.(evalc2.Config)
	pub := evalc2.PublicAssignment(ec, cp[0], p.ToBig(slot.C1.C1), p.ToBig(slot.PK.A), new(big.Int).SetBytes(oi.ComF[:]))
	if keys.VerifyOffchain(t.EvalC2.Entry.Curve, t.EvalC2.VK, pub, ep) != nil {
		return s.reject(orderID, "pi_eval fails")
	}
	start = s.mark("seller.check_order", start)
	// The slot's single partial decryption, pi_dec, claim.
	pd, efl, err := slot.PartialDecryptOnce(p, p.FromBig(cp[0]), rand.Reader)
	if err != nil { // the key already answered: the order cannot be served
		if _, _, err := s.reject(orderID, err.Error()); err != nil {
			return Rejected, "", err
		}
		return s.retire(oi.Slot, err.Error())
	}
	start = s.mark("seller.partial_decrypt", start)
	asg, _, err := decproof.Assign(dc, orderID, cp[0], slot.KeyWitness.S, slot.Eta, pd, efl)
	if err != nil {
		return Skipped, "", err
	}
	_, proof, err := keys.Prove(t.Dec.Entry.Curve, t.Dec.CS, t.Dec.PK, asg, onchain.ProverOption())
	if err != nil {
		return Skipped, "", err
	}
	pb, err := onchain.ProofBytes(proof)
	if err != nil {
		return Skipped, "", err
	}
	start = s.mark("seller.prove", start)
	if out, why, done, err := s.beforeClaim(orderID, oi, slot); done {
		return out, why, err
	}
	start = clock.Now()
	rcpt, err := s.M.ClaimDec(s.Acct, orderID, pd, pb, 1_000_000)
	s.gas("claimDec", rcpt)
	s.mark("seller.claim_tx", start)
	if err == nil && rcpt.Status != types.ReceiptStatusSuccessful {
		err = errors.New("claim reverted")
	}
	if err != nil {
		return s.claimFailed(orderID, oi, err)
	}
	s.erase(oi.Slot)
	return Claimed, "", nil
}
