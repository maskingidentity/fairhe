package hashes

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestCoinSeedDeterministicAndSeparated(t *testing.T) {
	a := Case1KeyCoin([]byte("buyer-1"), 0, LabelPkA)
	if a != Case1KeyCoin([]byte("buyer-1"), 0, LabelPkA) {
		t.Fatal("H_coin is not deterministic")
	}
	distinct := map[[32]byte]string{a: "base"}
	for name, s := range map[string][32]byte{
		"other key index": Case1KeyCoin([]byte("buyer-1"), 1, LabelPkA),
		"other buyer":     Case1KeyCoin([]byte("buyer-2"), 0, LabelPkA),
		"other label":     Case1KeyCoin([]byte("buyer-1"), 0, LabelC1A),
		"case 2 slot":     Case2SlotCoin([]byte("buyer-1"), nil, 0, LabelPkA),
		"case 2 c1":       Case2SlotCoin([]byte("seller"), []byte("com"), 3, LabelC1A),
		"case 2 pk":       Case2SlotCoin([]byte("seller"), []byte("com"), 3, LabelPkA),
		"case 2 slot 4":   Case2SlotCoin([]byte("seller"), []byte("com"), 4, LabelPkA),
	} {
		if prev, ok := distinct[s]; ok {
			t.Fatalf("seed for %q collides with %q", name, prev)
		}
		distinct[s] = name
	}
	// Length prefixes make the encoding injective: moving a byte across the
	// boundary of two parts changes the seed.
	if CoinSeed("l", []byte("ab"), []byte("c")) == CoinSeed("l", []byte("a"), []byte("bc")) {
		t.Fatal("part boundaries are not encoded")
	}
}

// TestCoinPRNGKnownAnswer pins the KeyedPRNG expansion: if a Lattigo upgrade
// changed the stream, every verifier would derive different public coins.
func TestCoinPRNGKnownAnswer(t *testing.T) {
	seed := Case2SlotCoin([]byte("seller"), []byte("com"), 0, LabelPkA)
	prng, err := CoinPRNG(seed)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	if _, err := prng.Read(buf); err != nil {
		t.Fatal(err)
	}
	const wantSeed = "3fceea9264cff8e3c27ba7416373263b0841f2cfcbfa92fc4b1ef4e15aa717c0"
	const wantStream = "78255ce6b945ac564d027144d360830e0d4a1893cb2a52a49dfe070ed4b6b31d"
	if got := hex.EncodeToString(seed[:]); got != wantSeed {
		t.Errorf("seed KAT: got %s", got)
	}
	if got := hex.EncodeToString(buf); got != wantStream {
		t.Errorf("stream KAT: got %s", got)
	}
	// A second PRNG from the same seed replays the stream.
	prng2, _ := CoinPRNG(seed)
	buf2 := make([]byte, 32)
	prng2.Read(buf2)
	if !bytes.Equal(buf, buf2) {
		t.Fatal("KeyedPRNG is not reproducible")
	}
}

func TestPtBelowModulus(t *testing.T) {
	r := BLSModulus()
	if r.BitLen() != 255 {
		t.Fatalf("r_bls has %d bits", r.BitLen())
	}
	for i := 0; i < 64; i++ {
		var vh, hD [32]byte
		vh[0], vh[31], hD[5] = 0x01, byte(i), byte(3*i)
		z := Pt(vh, hD)
		if z.Sign() < 0 || z.Cmp(r) >= 0 {
			t.Fatalf("z = %s not in [0, r_bls)", z)
		}
		want := new(big.Int).SetBytes(crypto.Keccak256([]byte(TagPt), vh[:], hD[:]))
		want.Mod(want, r)
		if z.Cmp(want) != 0 {
			t.Fatal("Pt differs from keccak256(TagPt || vh || h_D) mod r_bls")
		}
	}
}
