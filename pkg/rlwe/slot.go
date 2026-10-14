package rlwe

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"sync"

	"fairhe/pkg/hashes"

	"github.com/tuneinsight/lattigo/v6/ring"
)

// Slot is a Case 2 seller slot prepared at registration (paper Section 3.4.2):
// a fresh session key whose uniform component is a public coin, the data
// ciphertext c1 = Enc_S(x) under the secret key with a public-coin c1,1, and
// the salted digest h_s = H_dig(s || eta_s) that pi_key, pi_enc and pi_dec
// open. The session key releases one partial decryption only.
type Slot struct {
	Index      uint64
	SK         *SecretKey
	PK         *PublicKey
	C1         *Ciphertext
	Eta        []byte   // salt of h_s, kept by the seller
	HS         *big.Int // h_s over BN254, the field of the Case 2 circuits
	KeyWitness *KeyWitness
	EncWitness *EncWitness

	mu     sync.Mutex
	used   bool
	erased bool
}

// LabelHS is the digest label of the slot secret.
const LabelHS = "h_s"

// SlotCoins returns the public-coin uniform components of slot i:
// a = H_coin(id_S || Com(x) || i || "pk.a") and c1,1 = H_coin(... || "c1.a").
func (p *Params) SlotCoins(sellerID, comX []byte, index uint64) (a, c11 ring.Poly, err error) {
	a, err = p.CoinPoly(hashes.Case2SlotCoin(sellerID, comX, index, hashes.LabelPkA))
	if err != nil {
		return
	}
	c11, err = p.CoinPoly(hashes.Case2SlotCoin(sellerID, comX, index, hashes.LabelC1A))
	return
}

// PrepareSlot generates slot i for the seller's data message msg (S_bar).
func (p *Params) PrepareSlot(sellerID, comX []byte, index uint64, msg []int64, rng io.Reader) (*Slot, error) {
	if p.lit.Case != Case2 {
		return nil, fmt.Errorf("rlwe: slots belong to Case 2")
	}
	if rng == nil {
		rng = rand.Reader
	}
	a, c11, err := p.SlotCoins(sellerID, comX, index)
	if err != nil {
		return nil, err
	}
	sk, pk, kw, err := p.KeyGen(a, rng)
	if err != nil {
		return nil, err
	}
	c1, ew, err := p.EncryptSK(sk, msg, c11, rng)
	if err != nil {
		return nil, err
	}
	eta := make([]byte, hashes.SaltBytes)
	if _, err := io.ReadFull(rng, eta); err != nil {
		return nil, err
	}
	hs, err := hashes.DigSecret(hashes.BN254, LabelHS, sk.S, eta)
	if err != nil {
		return nil, err
	}
	return &Slot{Index: index, SK: sk, PK: pk, C1: c1, Eta: eta, HS: hs, KeyWitness: kw, EncWitness: ew}, nil
}

// CheckSlotCoins is the buyer's check before it orders: the uniform
// components of the slot key and of c1 equal the public coins of slot i.
func (p *Params) CheckSlotCoins(sellerID, comX []byte, index uint64, pk *PublicKey, c1 *Ciphertext) error {
	a, c11, err := p.SlotCoins(sellerID, comX, index)
	if err != nil {
		return err
	}
	if !p.equal(a, pk.A) {
		return fmt.Errorf("rlwe: slot %d: a is not the public coin", index)
	}
	if !p.equal(c11, c1.C1) {
		return fmt.Errorf("rlwe: slot %d: c1,1 is not the public coin", index)
	}
	return nil
}

// PartialDecryptOnce releases the slot's single partial decryption of
// c2,1; any later call fails, so the session key never answers twice.
func (s *Slot) PartialDecryptOnce(p *Params, c21 ring.Poly, rng io.Reader) (*big.Int, *big.Int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used {
		return nil, nil, fmt.Errorf("rlwe: slot %d has already released its partial decryption", s.Index)
	}
	pd, efl, err := p.PartialDecrypt(s.SK, c21, rng)
	if err != nil {
		return nil, nil, err
	}
	s.used = true
	return pd, efl, nil
}

// Used reports whether the slot key has been used.
func (s *Slot) Used() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.used
}

// Withdraw undoes the release of a partial decryption that was computed but
// never sent: the seller rejected the order before broadcasting its claim,
// so the session key has not answered and the slot may serve another order.
// It must not be called once the
// claim has been broadcast, and has no effect after Erase.
func (s *Slot) Withdraw() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.erased {
		s.used = false
	}
}

// Erase overwrites the session secret, its salt and the witnesses that hold
// them once the slot is claimed or retired (a recommendation outside the
// model); the slot can then neither decrypt nor prove.
func (s *Slot) Erase() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.SK != nil {
		clear(s.SK.S)
	}
	if s.KeyWitness != nil {
		clear(s.KeyWitness.S)
		clear(s.KeyWitness.EPk)
	}
	if s.EncWitness != nil {
		clear(s.EncWitness.E)
	}
	clear(s.Eta)
	s.used, s.erased = true, true
}
