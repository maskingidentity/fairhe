// Package hashes implements the domain-separated hash instances of the
// paper (Section 2.3, Setup (iv)):
//
//   - H_coin, the public coins from which the uniform components of keys and
//     ciphertexts are derived (SHA-256 seed, expanded by Lattigo's KeyedPRNG);
//   - H_dig, the SNARK-friendly digests by which the ledger records bulky
//     values and, salted, session secrets (dig.go);
//   - H_pt, the evaluation point of the blob link, keccak256 reduced modulo
//     the BLS12-381 scalar field order r_bls.
//
// Every instance absorbs its own domain tag first, so outputs of different
// instances never coincide by construction, and every variable-length input
// is length-prefixed, so the encodings are injective.
package hashes

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

// Domain tags of the three instances.
const (
	TagCoin = "fairhe/v8/H_coin"
	TagDig  = "fairhe/v8/H_dig"
	TagPt   = "fairhe/v8/H_pt"
)

// Labels of the uniform components derived from public coins ("a label per
// component", paper Section 3.4.2).
const (
	// LabelPkA is the uniform component a of a public key pk = (b, a).
	LabelPkA = "pk.a"
	// LabelC1A is the uniform component c_{1,1} of the Case 2 data ciphertext.
	LabelC1A = "c1.a"
)

// CoinSeed returns the 32-byte public-coin seed
//
//	H_coin(part_1 || ... || part_k || label)
//	  = SHA-256(TagCoin || enc(part_1) || ... || enc(part_k) || enc(label)),
//
// with enc(x) = len(x) as 8-byte big-endian || x.
func CoinSeed(label string, parts ...[]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(TagCoin))
	for _, p := range parts {
		writeLenPrefixed(h, p)
	}
	writeLenPrefixed(h, []byte(label))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Case1KeyCoin is the seed of the uniform component of a Case 1 buyer key:
// H_coin(id_B || key index || label).
func Case1KeyCoin(buyerID []byte, keyIndex uint64, label string) [32]byte {
	return CoinSeed(label, buyerID, u64(keyIndex))
}

// Case2SlotCoin is the seed of a uniform component of a Case 2 slot:
// H_coin(id_S || Com(x) || i || label), where the contract assigns i.
func Case2SlotCoin(sellerID, comX []byte, slot uint64, label string) [32]byte {
	return CoinSeed(label, sellerID, comX, u64(slot))
}

// CoinPRNG expands a coin seed with Lattigo's KeyedPRNG (a BLAKE2b XOF keyed
// by the seed). Use a fresh PRNG per polynomial: Lattigo's uniform sampler
// buffers 1024 bytes of the stream, so sharing one PRNG across polynomials
// would make their values depend on the call order.
func CoinPRNG(seed [32]byte) (*sampling.KeyedPRNG, error) {
	return sampling.NewKeyedPRNG(seed[:])
}

// BLSModulus returns r_bls, the order of the BLS12-381 scalar field (the
// EIP-4844 BLS_MODULUS).
func BLSModulus() *big.Int { return blsfr.Modulus() }

// Pt returns the blob evaluation point
//
//	z = H_pt(vh || h_D) = keccak256(TagPt || vh || h_D) mod r_bls,
//
// which the settlement contract recomputes from blobhash(0) and the recorded
// digest h_D (both fixed-length, so no length prefixes are needed).
func Pt(vh, hD [32]byte) *big.Int {
	d := crypto.Keccak256([]byte(TagPt), vh[:], hD[:])
	z := new(big.Int).SetBytes(d)
	return z.Mod(z, blsfr.Modulus())
}

func writeLenPrefixed(h interface{ Write([]byte) (int, error) }, b []byte) {
	h.Write(u64(uint64(len(b))))
	h.Write(b)
}

func u64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}
