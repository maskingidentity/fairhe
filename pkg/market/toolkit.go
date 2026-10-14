package market

import (
	"fmt"
	"math/big"

	"fairhe/pkg/hashes"
	"fairhe/pkg/rlwe"
	"fairhe/pkg/valuation"
	"fairhe/pkg/zk/keys"
	"fairhe/pkg/zk/registry"
	"fairhe/pkg/zk/valclass"
	"fairhe/pkg/zk/zkmeasure"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/ethereum/go-ethereum/crypto"
)

// Circuit is one set-up proof circuit with its keys.
type Circuit struct {
	Entry registry.Entry
	Rec   *keys.Record
	CS    constraint.ConstraintSystem
	PK    groth16.ProvingKey
	VK    groth16.VerifyingKey
}

// VKID returns the VK ID as bytes32.
func (c *Circuit) VKID() [32]byte {
	var id [32]byte
	copy(id[:], hexBytes(c.Rec.VKID))
	return id
}

// Toolkit holds the HE parameters, the class and the proof circuits of one
// parameter set: pi_key with pi_member and pi_eval for Case 1, pi_key with
// pi_enc, pi_eval and pi_dec for Case 2.
type Toolkit struct {
	Scale                                 registry.Scale
	Name                                  string
	P                                     *rlwe.Params
	Class                                 valclass.Class
	Key, Member, EvalC1, Enc, EvalC2, Dec *Circuit
}

// SetupToolkit sets up the circuits of a parameter set into dir.
func SetupToolkit(scale registry.Scale, params, dir string) (*Toolkit, error) {
	all, err := registry.All(scale)
	if err != nil {
		return nil, err
	}
	t := &Toolkit{Scale: scale, Name: params}
	for _, e := range all {
		if e.Params != params {
			continue
		}
		rec, cs, pk, vk, err := keys.Setup(e, dir, scale)
		if err != nil {
			return nil, err
		}
		c := &Circuit{Entry: e, Rec: rec, CS: cs, PK: pk, VK: vk}
		t.P = e.RLWE
		if e.Class != nil {
			t.Class = *e.Class
		}
		switch e.Circuit {
		case registry.PiKey:
			t.Key = c
		case registry.PiMember:
			t.Member = c
		case registry.PiEvalC1:
			t.EvalC1 = c
		case registry.PiEnc:
			t.Enc = c
		case registry.PiEvalC2:
			t.EvalC2 = c
		case registry.PiDec:
			t.Dec = c
		}
	}
	if t.P == nil {
		return nil, fmt.Errorf("market: no circuits for %s", params)
	}
	return t, nil
}

// Case returns the protocol case of the toolkit.
func (t *Toolkit) Case() rlwe.Case { return t.P.Case() }

// Field is the digest field of the case.
func (t *Toolkit) Field() hashes.Field {
	if t.Case() == rlwe.Case1 {
		return hashes.BLS12381
	}
	return hashes.BN254
}

// QBits is the packing width of polynomial digests.
func (t *Toolkit) QBits() int { return new(big.Int).Sub(t.P.Q(), big.NewInt(1)).BitLen() }

// Terms is the digest of the offer's terms that the buyer recomputes: the
// parameter set, the scale and the class constants.
func (t *Toolkit) Terms() [32]byte {
	var out [32]byte
	cl := t.Class
	copy(out[:], crypto.Keccak256([]byte(fmt.Sprintf("%s/%s/cols=%d/wmax=%d/beta=%d/unit=%d/xbits=%d/sigma=%d",
		t.Name, t.Scale, cl.Cols, cl.WMax, cl.Beta, cl.Unit, cl.XBits, t.P.SigmaFl()))))
	return out
}

// ClassBounds returns the class bounds for the margins of the parameters:
// those of package valuation at full scale, the generic ones of the reduced
// class otherwise.
func (t *Toolkit) ClassBounds() rlwe.ClassBounds {
	cl := t.Class
	if t.Scale == registry.Full {
		switch {
		case t.Case() == rlwe.Case1 && t.P.Scheme() == rlwe.BFV:
			return rlwe.ClassBounds{PtNormL1: valuation.SNormL1MaxInt(), FMax: new(big.Rat).SetInt(valuation.FMaxInt())}
		case t.Case() == rlwe.Case1:
			return rlwe.ClassBounds{PtNormL1: valuation.SNormL1MaxFixed(), FMax: valuation.FMaxFixed()}
		case t.P.Scheme() == rlwe.BFV:
			return rlwe.ClassBounds{PtNormL1: valuation.WHatNormL1MaxInt(), FMax: new(big.Rat).SetInt(valuation.FMaxInt())}
		default:
			return rlwe.ClassBounds{PtNormL1: valuation.WHatNormL1MaxFixed(), FMax: valuation.FMaxFixed()}
		}
	}
	sNorm := new(big.Int).Lsh(big.NewInt(int64(cl.M())), uint(cl.XBits))
	fmax := new(big.Rat).SetInt(new(big.Int).Mul(cl.WHatNormL1Max(), new(big.Int).Lsh(big.NewInt(1), uint(cl.XBits))))
	if t.P.Scheme() == rlwe.CKKS { // fixed-point units of 2^-40
		fmax.Quo(fmax, new(big.Rat).SetInt(new(big.Int).Lsh(big.NewInt(1), 2*valuation.FracBits)))
	}
	if t.Case() == rlwe.Case1 {
		return rlwe.ClassBounds{PtNormL1: sNorm, FMax: fmax}
	}
	return rlwe.ClassBounds{PtNormL1: cl.WHatNormL1Max(), FMax: fmax}
}

func hexBytes(s string) []byte {
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		fmt.Sscanf(s[2*i:2*i+2], "%02x", &out[i])
	}
	return out
}

// LoadOrSetupToolkit loads the circuits of a parameter set from the key
// directory's manifest, setting up (and recording) those that are missing.
func LoadOrSetupToolkit(scale registry.Scale, params, dir string) (*Toolkit, error) {
	all, err := registry.All(scale)
	if err != nil {
		return nil, err
	}
	m, err := keys.ReadManifest(dir, scale)
	if err != nil {
		m = &keys.Manifest{Scale: string(scale), Note: "local Groth16 setup (not a ceremony)"}
	}
	find := func(name string) *keys.Record {
		for i := range m.Records {
			if m.Records[i].Name == name {
				return &m.Records[i]
			}
		}
		return nil
	}
	t := &Toolkit{Scale: scale, Name: params}
	for _, e := range all {
		if e.Params != params {
			continue
		}
		var c *Circuit
		if rec := find(e.Name()); rec != nil {
			pk, vk, lerr := keys.LoadKeys(*rec, dir, e)
			if lerr == nil {
				cs, _, cerr := zkmeasure.Compile(e.Curve, e.New(), e.Circuit, e.Params)
				if cerr != nil {
					return nil, cerr
				}
				r := *rec
				if e.OnChain {
					if err := keys.EnsureVerifier(&r, vk, scale); err != nil {
						return nil, err
					}
				}
				c = &Circuit{Entry: e, Rec: &r, CS: cs, PK: pk, VK: vk}
			}
		}
		if c == nil {
			rec, cs, pk, vk, err := keys.Setup(e, dir, scale)
			if err != nil {
				return nil, err
			}
			m.Records = append(m.Records, *rec)
			if err := keys.WriteManifest(dir, m); err != nil {
				return nil, err
			}
			c = &Circuit{Entry: e, Rec: rec, CS: cs, PK: pk, VK: vk}
		}
		t.P = e.RLWE
		if e.Class != nil {
			t.Class = *e.Class
		}
		switch e.Circuit {
		case registry.PiKey:
			t.Key = c
		case registry.PiMember:
			t.Member = c
		case registry.PiEvalC1:
			t.EvalC1 = c
		case registry.PiEnc:
			t.Enc = c
		case registry.PiEvalC2:
			t.EvalC2 = c
		case registry.PiDec:
			t.Dec = c
		}
	}
	if t.P == nil {
		return nil, fmt.Errorf("market: no circuits for %s", params)
	}
	return t, nil
}
