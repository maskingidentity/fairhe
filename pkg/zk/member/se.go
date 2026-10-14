package member

import (
	"fmt"
	"io"
	"math/big"
	"math/bits"

	"fairhe/pkg/hashes"
	"fairhe/pkg/rlwe"
	"fairhe/pkg/zk/gadgets"
	"fairhe/pkg/zk/se"

	"github.com/consensys/gnark/frontend"
)

// SECircuit is pi_member made straight-line extractable for the weights w
// (option O2): the member relation, and
// (R, CT) is the encryption of the packed weights under the extraction key
// that the setup fixes (package se). An extractor holding the matching
// secret reads w from any accepting proof without rewinding.
type SECircuit struct {
	Member Circuit
	RX, RY frontend.Variable   `gnark:",public"`
	CT     []frontend.Variable `gnark:",public"`
	Rnd    frontend.Variable

	pk se.PublicKey
}

// seBits is the width of an offset weight w_j + w_max in [0, 2 w_max].
func seBits(cfg Config) int { return bits.Len64(uint64(2 * cfg.Class.WMax)) }

func sePer(cfg Config) int { return hashes.PackPerElement(hashes.BLS12381, seBits(cfg)) }

// SEElements is the number of field elements that carry the weights.
func SEElements(cfg Config) int { return (cfg.Class.Cols + sePer(cfg) - 1) / sePer(cfg) }

// NewSE returns an empty SE circuit for a configuration and extraction key.
func NewSE(cfg Config, pk se.PublicKey) *SECircuit {
	return &SECircuit{Member: *New(cfg), CT: make([]frontend.Variable, SEElements(cfg)), pk: pk}
}

// Define implements the member relation and the encryption of w.
func (c *SECircuit) Define(api frontend.API) error {
	if err := c.Member.Define(api); err != nil {
		return err
	}
	cfg := c.Member.cfg
	vals := make([]frontend.Variable, len(c.Member.W))
	for j, w := range c.Member.W {
		vals[j] = api.Add(w, cfg.Class.WMax) // in [0, 2 w_max]: the member relation range checks w
	}
	m := gadgets.Pack(api, vals, seBits(cfg), sePer(cfg))
	R, ct, err := se.EncryptCircuit(api, c.pk, c.Rnd, m)
	if err != nil {
		return err
	}
	api.AssertIsEqual(R.X, c.RX)
	api.AssertIsEqual(R.Y, c.RY)
	for j := range ct {
		api.AssertIsEqual(ct[j], c.CT[j])
	}
	return nil
}

// PackWeights returns the field elements that SECircuit encrypts.
func PackWeights(cfg Config, w []int64) ([]*big.Int, error) {
	vals := make([]*big.Int, len(w))
	for j, x := range w {
		vals[j] = big.NewInt(x + cfg.Class.WMax)
	}
	return hashes.PackBits(hashes.BLS12381, vals, seBits(cfg))
}

// UnpackWeights is the extractor's last step: the weights from the elements.
func UnpackWeights(cfg Config, elems []*big.Int) ([]int64, error) {
	b, per := seBits(cfg), sePer(cfg)
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(b)), big.NewInt(1))
	out := make([]int64, cfg.Class.Cols)
	for j := range out {
		e := elems[j/per]
		v := new(big.Int).Rsh(e, uint(b*(j%per)))
		v.And(v, mask)
		if !v.IsInt64() || v.Int64() > 2*cfg.Class.WMax {
			return nil, fmt.Errorf("member: weight %d out of range after extraction", j)
		}
		out[j] = v.Int64() - cfg.Class.WMax
	}
	return out, nil
}

// AssignSE returns the SE assignment of an order: the member assignment
// and a fresh encryption of the packed weights under pk.
func AssignSE(cfg Config, pk se.PublicKey, p *rlwe.Params, ct *rlwe.Ciphertext, w []int64, rhoF []byte, s []int64, eta []byte, ew *rlwe.EncWitness, rng io.Reader) (*SECircuit, error) {
	base, err := Assign(cfg, p, ct, w, rhoF, s, eta, ew)
	if err != nil {
		return nil, err
	}
	m, err := PackWeights(cfg, w)
	if err != nil {
		return nil, err
	}
	r, rx, ry, cts, err := se.Encrypt(pk, m, rng)
	if err != nil {
		return nil, err
	}
	c := &SECircuit{Member: *base, RX: rx, RY: ry, CT: make([]frontend.Variable, len(cts)), Rnd: r, pk: pk}
	for j, v := range cts {
		c.CT[j] = v
	}
	return c, nil
}
