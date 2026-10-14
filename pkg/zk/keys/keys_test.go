package keys

import (
	"crypto/rand"
	"testing"

	"fairhe/pkg/hashes"
	"fairhe/pkg/zk/keyproof"
	"fairhe/pkg/zk/registry"

	"github.com/consensys/gnark/backend/groth16"
)

// TestSetupRoundTrip sets up a small pi_key and reads its keys back; the
// verifying key must hash to the recorded VK ID.
func TestSetupRoundTrip(t *testing.T) {
	e, err := registry.Find(registry.Small, registry.PiKey, "case2_bfv")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, _, _, vk, err := Setup(e, dir, registry.Small)
	if err != nil {
		t.Fatal(err)
	}
	if id, _ := VKID(vk); id != rec.VKID {
		t.Fatal("VK ID of the in-memory key differs from the record")
	}
	if _, _, err := LoadKeys(*rec, dir, e); err != nil {
		t.Fatal(err)
	}
	bad := *rec
	bad.VKID = "0x00"
	if _, _, err := LoadKeys(bad, dir, e); err == nil {
		t.Fatal("LoadKeys accepted a key that does not match the manifest")
	}
	all, err := registry.All(registry.Full)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 14 {
		t.Fatalf("%d registry entries, want 14", len(all))
	}
}

// TestB8ForeignKey is test B8 off chain: a proof
// made with the keys of another setup of the same circuit does not verify
// under the key that the setup fixed, which the counterparty uses, while a
// proof under the fixed key does. The contract side is pkg/chain
// TestMarketRegistration and TestMarketCase2Rules.
func TestB8ForeignKey(t *testing.T) {
	e, err := registry.Find(registry.Small, registry.PiKey, "case2_bfv")
	if err != nil {
		t.Fatal(err)
	}
	_, cs, pk, vk, err := Setup(e, t.TempDir(), registry.Small)
	if err != nil {
		t.Fatal(err)
	}
	_, cs2, pk2, vk2, err := Setup(e, t.TempDir(), registry.Small)
	if err != nil {
		t.Fatal(err)
	}
	if a, b := mustVKID(t, vk), mustVKID(t, vk2); a == b {
		t.Fatal("two setups gave the same VK ID")
	}
	p, cfg := e.RLWE, e.Config.(keyproof.Config)
	a, err := p.CoinPoly(hashes.Case2SlotCoin([]byte("seller"), []byte("com"), 1, hashes.LabelPkA))
	if err != nil {
		t.Fatal(err)
	}
	_, key, w, err := p.KeyGen(a, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	eta := make([]byte, hashes.SaltBytes)
	rand.Read(eta)
	asg, h, err := keyproof.Assign(cfg, p, key, w, eta)
	if err != nil {
		t.Fatal(err)
	}
	pub := keyproof.PublicAssignment(cfg, p, key, h)
	good, _, err := Prove(e.Curve, cs, pk, asg)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyOffchain(e.Curve, vk, pub, good); err != nil {
		t.Fatalf("the fixed key rejects its own proof: %v", err)
	}
	foreign, _, err := Prove(e.Curve, cs2, pk2, asg)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyOffchain(e.Curve, vk, pub, foreign) == nil {
		t.Fatal("a proof under another setup verifies under the fixed key")
	}
}

func mustVKID(t *testing.T, vk groth16.VerifyingKey) string {
	t.Helper()
	id, err := VKID(vk)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
