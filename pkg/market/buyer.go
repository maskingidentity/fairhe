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
	"fairhe/pkg/rlwe"
	"fairhe/pkg/valuation"
	"fairhe/pkg/zk/decproof"
	"fairhe/pkg/zk/encproof"
	"fairhe/pkg/zk/evalc1"
	"fairhe/pkg/zk/evalc2"
	"fairhe/pkg/zk/keyproof"
	"fairhe/pkg/zk/keys"
	"fairhe/pkg/zk/member"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// RetentionBlocks is the blob retention window W: 4096 epochs of 32 slots
// of 12 s, about 18 days, in blocks.
const RetentionBlocks = 4096 * 32

// RetrievalMargin is the margin, one epoch in blocks, that the buyer keeps
// between its refund time and the end of the retention window W.
const RetrievalMargin = 32

// Buyer is the buyer's state machine: in Case 1 it registers a public-coin
// key with pi_key; before it orders it checks the terms (decoding condition
// or tolerance), that the offer names the verification keys fixed for those
// terms and, in Case 2, the slot's public coins, pi_key and pi_enc; it orders
// only with T_min <= T_ref - T_order <= T_max and T_ref - T_order < W -
// margin; after ordering it waits for an accepted claim and decodes, or
// refunds after T_ref; in Case 2 it deletes c2,0 once it has decoded.
type Buyer struct {
	Acct  *chain.Account
	M     *chain.Market
	Board Board
	Net   *BlobNet
	T     *Toolkit
	W     uint64
	// Archive, when set, serves a deliverable blob that the network no
	// longer retains (option O7); what it serves is checked like the rest.
	Archive *Archive

	keyIndex uint64
	sk       *rlwe.SecretKey
	pk       *rlwe.PublicKey
	keyW     *rlwe.KeyWitness
	eta      []byte
	keyID    [32]byte
	pending  map[string]*pendingOrder

	// Trace and Gas as for the seller.
	Trace func(stage string, d time.Duration)
	Gas   func(tx string, rcpt *types.Receipt)
}

func (b *Buyer) mark(stage string, start clock.Reading) clock.Reading {
	if b.Trace != nil {
		b.Trace(stage, clock.Since(start))
	}
	return clock.Now()
}

func (b *Buyer) gas(tx string, rcpt *types.Receipt) {
	if b.Gas != nil && rcpt != nil {
		b.Gas(tx, rcpt)
	}
}

type pendingOrder struct {
	tRef uint64
	c20  *ring.Poly // Case 2: kept until decoding
}

// Result is the outcome of an order for the buyer.
type Result struct {
	Refunded bool
	Value    *big.Int // BFV
	Real     *big.Rat // CKKS
}

// NewBuyer returns a buyer whose bulky values go on board and who reads
// deliverable blobs from net; its retention window W is the network's.
func NewBuyer(acct *chain.Account, m *chain.Market, board Board, net *BlobNet, t *Toolkit) *Buyer {
	return &Buyer{Acct: acct, M: m, Board: board, Net: net, T: t, W: net.W, pending: map[string]*pendingOrder{}}
}

// RegisterKey registers a Case 1 key: a from the public coin of
// (buyer, index), b with pi_key on the board, digests on the ledger.
func (b *Buyer) RegisterKey(index uint64) (*types.Receipt, error) {
	t, p := b.T, b.T.P
	start := clock.Now()
	a, err := p.CoinPoly(hashes.Case1KeyCoin(b.Acct.Addr.Bytes(), index, hashes.LabelPkA))
	if err != nil {
		return nil, err
	}
	sk, pk, kw, err := p.KeyGen(a, rand.Reader)
	if err != nil {
		return nil, err
	}
	eta := make([]byte, hashes.SaltBytes)
	rand.Read(eta)
	kc := t.Key.Entry.Config.(keyproof.Config)
	ka, hsb, err := keyproof.Assign(kc, p, pk, kw, eta)
	if err != nil {
		return nil, err
	}
	proof, _, err := keys.Prove(t.Key.Entry.Curve, t.Key.CS, t.Key.PK, ka)
	if err != nil {
		return nil, err
	}
	polys := [][]*big.Int{p.ToBig(pk.B), p.ToBig(pk.A)}
	hpk, err := hashes.DigPoly(hashes.BLS12381, evalc1.LabelHPk, append(polys[0], polys[1]...), t.QBits())
	if err != nil {
		return nil, err
	}
	hpkB := hashes.Bytes32(hpk)
	bv, err := PackPolys(t.QBits(), polys[0]) // a is the public coin: the seller recomputes it (option O5)
	if err != nil {
		return nil, err
	}
	start = b.mark("buyer.keygen_and_pi_key", start)
	rcpts, err := b.Board.Post(b.Acct, Item{Digest: hpkB, Label: LabelPiKey, Value: bv, Proof: proof})
	for _, r := range rcpts {
		b.gas("post_key", r)
	}
	if err != nil {
		return nil, err
	}
	start = b.mark("buyer.post_key", start)
	keyID, rcpt, err := b.M.RegisterKey(b.Acct, index, hpkB, hashes.Bytes32(hsb))
	b.gas("registerKey", rcpt)
	b.mark("buyer.register_key_tx", start)
	if err != nil {
		return rcpt, err
	}
	b.keyIndex, b.sk, b.pk, b.keyW, b.eta, b.keyID = index, sk, pk, kw, eta, keyID
	return rcpt, nil
}

// CheckOffer is the buyer's check before it orders: the terms are those of
// its toolkit and meet the decoding condition or tolerance for the class;
// the offer's verification key IDs are those the setup fixed for these
// terms, whose circuit constants the toolkit holds (test B8); in Case 2
// each slot's key and data ciphertext sit on their public coins and carry
// valid pi_key and pi_enc.
func (b *Buyer) CheckOffer(offerID *big.Int) error {
	t, p := b.T, b.T.P
	defer b.mark("buyer.check_offer", clock.Now())
	o, err := b.M.OfferInfo(offerID)
	if err != nil {
		return err
	}
	if o.CaseId != uint8(t.Case()) || o.Terms != t.Terms() {
		return errors.New("market: unexpected terms")
	}
	var claimVk, inputVk [32]byte
	if t.Case() == rlwe.Case1 {
		claimVk, inputVk = t.EvalC1.VKID(), t.Member.VKID()
	} else {
		claimVk, inputVk = t.Dec.VKID(), t.Enc.VKID()
	}
	if o.ClaimVk != claimVk || o.KeyVk != t.Key.VKID() || o.InputVk != inputVk {
		return errors.New("market: the offer's verification keys are not those fixed for its terms")
	}
	if rep := p.CheckMargins(t.ClassBounds()); !rep.OK() {
		return fmt.Errorf("market: the terms fail their margins: %v", rep.Failures)
	}
	if t.Case() == rlwe.Case1 {
		return nil
	}
	for i := uint16(1); i <= o.Q; i++ {
		si, err := b.M.SlotInfo(offerID, i)
		if err != nil {
			return err
		}
		if si.State != 0 {
			continue
		}
		pk, c1, kp, ep, err := b.slotValues(o, i, si)
		if err != nil {
			return fmt.Errorf("market: slot %d: %w", i, err)
		}
		hs := new(big.Int).SetBytes(si.HS[:])
		kc := t.Key.Entry.Config.(keyproof.Config)
		if err := keys.VerifyOffchain(t.Key.Entry.Curve, t.Key.VK, keyproof.PublicAssignment(kc, p, pk, hs), kp); err != nil {
			return fmt.Errorf("market: slot %d: pi_key: %w", i, err)
		}
		ec := t.Enc.Entry.Config.(encproof.Config)
		if err := keys.VerifyOffchain(t.Enc.Entry.Curve, t.Enc.VK, encproof.PublicAssignment(ec, p, c1, new(big.Int).SetBytes(o.ComX[:]), hs), ep); err != nil {
			return fmt.Errorf("market: slot %d: pi_enc: %w", i, err)
		}
	}
	return nil
}

// slotValues completes slot i's key and data ciphertext and returns them
// with pi_key and pi_enc: b and c1,0 are fetched from the seller's postings
// by their digests, a and c1,1 are the public coins of (seller, Com(x), i),
// and each digest must hold over the whole value (option O5), so a slot
// whose key or c1 is off its public coins fails here.
func (b *Buyer) slotValues(o *chain.OfferInfo, i uint16, si *chain.SlotInfo) (pk *rlwe.PublicKey, c1 *rlwe.Ciphertext, kp, ep []byte, err error) {
	t, p := b.T, b.T.P
	a, c11, err := p.SlotCoins(o.Seller.Bytes(), o.ComX[:], uint64(i))
	if err != nil {
		return
	}
	get := func(h [32]byte, label, proofLabel string, coin []*big.Int) ([]*big.Int, []byte, error) {
		raw, proof, err := b.Board.Fetch(o.Seller, h, proofLabel)
		if err != nil {
			return nil, nil, err
		}
		polys, err := UnpackPolys(raw, t.QBits(), p.N(), 1)
		if err != nil {
			return nil, nil, err
		}
		d, err := hashes.DigPoly(hashes.BN254, label, append(polys[0], coin...), t.QBits())
		if err != nil || hashes.Bytes32(d) != h {
			return nil, nil, errors.New("value does not match its digest with its public coin")
		}
		return polys[0], proof, nil
	}
	bp, kp, err := get(si.HPk, LabelHPk, LabelPiKey, p.ToBig(a))
	if err != nil {
		return
	}
	c10, ep, err := get(si.HC1, LabelHC1, LabelPiEnc, p.ToBig(c11))
	if err != nil {
		return
	}
	return &rlwe.PublicKey{B: p.FromBig(bp), A: a}, &rlwe.Ciphertext{C0: p.FromBig(c10), C1: c11}, kp, ep, nil
}

// Order places an order for slot with the weights w such that
// T_ref - T_order = tRefDelta when the order is included in the next block
// (the contract measures from the including block), within the offer's
// [T_min, T_max] and the W rule (else it pays nothing); the evaluation input
// and its proof are posted on the board under the input's digest first.
func (b *Buyer) Order(offerID *big.Int, slot uint16, w []int64, tRefDelta uint64) (*big.Int, *types.Receipt, error) {
	t, p := b.T, b.T.P
	if tRefDelta+RetrievalMargin >= b.W {
		return nil, nil, errors.New("market: refund time beyond the blob retention window")
	}
	o, err := b.M.OfferInfo(offerID)
	if err != nil {
		return nil, nil, err
	}
	if tRefDelta < o.TMin || tRefDelta > o.TMax {
		return nil, nil, fmt.Errorf("market: refund time %d blocks ahead is outside [%d, %d]", tRefDelta, o.TMin, o.TMax)
	}
	rhoF := make([]byte, hashes.SaltBytes)
	rand.Read(rhoF)
	comF, err := t.Class.CommitF(t.Field(), w, rhoF)
	if err != nil {
		return nil, nil, err
	}
	wh := valuation.EncodeForward(t.Class.Expand(w), p.N())
	now, err := b.M.Env.BlockNumber()
	if err != nil {
		return nil, nil, err
	}
	tRef := now + 1 + tRefDelta // the order lands in block now + 1
	po := &pendingOrder{tRef: tRef}
	start := clock.Now()
	var hInput [32]byte
	var item Item
	if t.Case() == rlwe.Case1 {
		if b.sk == nil {
			return nil, nil, errors.New("market: register a key first")
		}
		seed, a1, err := p.FreshSeededUniform(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		c, ew, err := p.EncryptSK(b.sk, wh, a1, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		cp := [][]*big.Int{p.ToBig(c.C0), p.ToBig(c.C1)}
		hc, err := hashes.DigPoly(hashes.BLS12381, evalc1.LabelHC, append(cp[0], cp[1]...), t.QBits())
		if err != nil {
			return nil, nil, err
		}
		hInput = hashes.Bytes32(hc)
		mc := t.Member.Entry.Config.(member.Config)
		ma, err := member.Assign(mc, p, c, w, rhoF, b.sk.S, b.eta, ew)
		if err != nil {
			return nil, nil, err
		}
		proof, _, err := keys.Prove(t.Member.Entry.Curve, t.Member.CS, t.Member.PK, ma)
		if err != nil {
			return nil, nil, err
		}
		v, err := PackWithSeed(t.QBits(), seed, cp[0]) // a' travels as its seed (option O5)
		if err != nil {
			return nil, nil, err
		}
		item = Item{Digest: hInput, Label: LabelPiMember, Value: v, Proof: proof}
	} else {
		si, err := b.M.SlotInfo(offerID, slot)
		if err != nil {
			return nil, nil, err
		}
		pk, c1, _, _, err := b.slotValues(o, slot, si)
		if err != nil {
			return nil, nil, err
		}
		c2, rw, err := p.EvalRerand(pk, c1, wh, rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		c21 := p.ToBig(c2.C1)
		dc := t.Dec.Entry.Config.(decproof.Config)
		hc, err := decproof.DigestC21(dc, c21)
		if err != nil {
			return nil, nil, err
		}
		hInput = hashes.Bytes32(hc)
		ec := t.EvalC2.Entry.Config.(evalc2.Config)
		ea, err := evalc2.Assign(ec, p, c21, p.ToBig(c1.C1), p.ToBig(pk.A), w, rhoF, rw)
		if err != nil {
			return nil, nil, err
		}
		proof, _, err := keys.Prove(t.EvalC2.Entry.Curve, t.EvalC2.CS, t.EvalC2.PK, ea)
		if err != nil {
			return nil, nil, err
		}
		v, err := PackPolys(t.QBits(), c21)
		if err != nil {
			return nil, nil, err
		}
		item = Item{Digest: hInput, Label: LabelPiEval, Value: v, Proof: proof}
		c20 := p.Copy(c2.C0)
		po.c20 = &c20
	}
	start = b.mark("buyer.prepare_order", start)
	rcpts, err := b.Board.Post(b.Acct, item)
	for _, r := range rcpts {
		b.gas("post_order", r)
	}
	if err != nil {
		return nil, nil, err
	}
	start = b.mark("buyer.post_order", start)
	id, rcpt, err := b.M.Order(b.Acct, o.Price, offerID, slot, tRef, hashes.Bytes32(comF), hInput, b.keyID)
	b.gas("order", rcpt)
	b.mark("buyer.order_tx", start)
	if err != nil {
		return nil, rcpt, err
	}
	b.pending[id.String()] = po
	return id, rcpt, nil
}

// Await checks an order: with an accepted claim it reads the deliverable
// and decodes; past the refund time without one it refunds; otherwise it
// returns nil (still waiting).
func (b *Buyer) Await(orderID *big.Int) (*Result, error) {
	t, p := b.T, b.T.P
	po, ok := b.pending[orderID.String()]
	if !ok {
		return nil, errors.New("market: unknown order")
	}
	// Only an accepted claim emits Claimed: the deliverable of a reverted
	// claim, though public, is never used (test E6).
	ev, err := b.M.ClaimOf(orderID)
	if err != nil {
		return nil, err
	}
	if ev != nil {
		defer b.mark("buyer.decode", clock.Now())
		res := &Result{}
		var x *big.Int
		modulus := p.Q()
		if t.Case() == rlwe.Case2 {
			x = p.Recover(*po.c20, ev["p"].(*big.Int))
			po.c20 = nil // forward security: c2,0 is deleted after decoding
		} else {
			vh := ev["versionedHash"].([32]byte)
			now, err := b.M.Env.BlockNumber()
			if err != nil {
				return nil, err
			}
			bl, ok := b.Net.Fetch(vh, now)
			if !ok && b.Archive != nil { // past the retention window (option O7)
				bl, ok = b.Archive.Fetch(vh)
			}
			if !ok {
				return nil, errors.New("market: blob not retrievable")
			}
			if err := blob.Check(bl, vh); err != nil {
				return nil, err
			}
			cfg := t.EvalC1.Entry.Config.(evalc1.Config)
			k := (p.N() + 1 + cfg.DPer - 1) / cfg.DPer
			coeffs, err := blob.Unpack(blob.Elements(bl, k), cfg.DBits, cfg.DPer, p.N()+1)
			if err != nil {
				return nil, err
			}
			x = p.DecryptDeliverable(b.sk, &rlwe.Deliverable{D0: coeffs[0], D1: coeffs[1:]})
			modulus = p.QDel()
		}
		if p.Scheme() == rlwe.BFV {
			res.Value = p.DecodeBFV(x, modulus)
		} else {
			res.Real = p.DecodeCKKS(x, modulus)
		}
		delete(b.pending, orderID.String())
		return res, nil
	}
	now, err := b.M.Env.BlockNumber()
	if err != nil {
		return nil, err
	}
	if now < po.tRef {
		return nil, nil
	}
	rcpt, err := b.M.Refund(b.Acct, orderID, 0)
	b.gas("refund", rcpt)
	if err != nil {
		return nil, err
	}
	if rcpt.Status != types.ReceiptStatusSuccessful {
		return nil, errors.New("market: refund reverted")
	}
	delete(b.pending, orderID.String())
	return &Result{Refunded: true}, nil
}

// HoldsC20 reports whether the buyer still holds c2,0 of an order.
func (b *Buyer) HoldsC20(orderID *big.Int) bool {
	po, ok := b.pending[orderID.String()]
	return ok && po.c20 != nil
}
