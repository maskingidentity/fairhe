// Package registry lists the proof circuits with their verification-key
// constants: which circuit serves which parameter set, on
// which curve, whether the settlement contract verifies it, and the
// constants (ring degree, moduli, flood width, class) that a verification
// key fixes. Scale "full" is the running example of the paper; scale
// "small" is a reduced instance (N = 64, Cols = 2) for integration tests.
package registry

import (
	"fmt"
	"math/big"

	"fairhe/pkg/rlwe"
	"fairhe/pkg/valuation"
	"fairhe/pkg/zk/decproof"
	"fairhe/pkg/zk/encproof"
	"fairhe/pkg/zk/evalc1"
	"fairhe/pkg/zk/evalc2"
	"fairhe/pkg/zk/keyproof"
	"fairhe/pkg/zk/member"
	"fairhe/pkg/zk/valclass"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

// Circuit names.
const (
	PiKey    = "pi_key"
	PiMember = "pi_member"
	PiEnc    = "pi_enc"
	PiEvalC2 = "pi_eval_c2"
	PiDec    = "pi_dec"
	PiEvalC1 = "pi_eval_c1"
)

// Scale selects the instance size.
type Scale string

const (
	Full  Scale = "full"
	Small Scale = "small"
)

// Entry is one verification key to set up.
type Entry struct {
	Circuit   string
	Params    string
	Curve     ecc.ID
	OnChain   bool
	New       func() frontend.Circuit
	Constants map[string]string
	// Config is the circuit configuration (keyproof.Config, member.Config, ...).
	Config any
	// RLWE are the HE parameters the circuit was configured for.
	RLWE *rlwe.Params
	// Class is the function class (nil for pi_key and pi_dec).
	Class *valclass.Class
}

// Name returns "<circuit>_<params>".
func (e Entry) Name() string { return e.Circuit + "_" + e.Params }

// ParamsFor returns the HE parameters of a set at a scale.
func ParamsFor(lit rlwe.ParamsLiteral, scale Scale, cl valclass.Class) (*rlwe.Params, error) {
	if scale == Small {
		lit.LogN, lit.J = 6, cl.M()-1
	}
	return rlwe.NewParams(lit)
}

// ClassFor returns the class of a parameter set at a scale.
func ClassFor(lit rlwe.ParamsLiteral, scale Scale) valclass.Class {
	cols := valuation.Cols
	if scale == Small {
		cols = 2
	}
	if lit.Scheme == rlwe.BFV {
		return valclass.BFV(cols)
	}
	return valclass.CKKS(cols)
}

// sNormL1 is the class bound on ||S_bar||_1 at the plaintext scale.
func sNormL1(lit rlwe.ParamsLiteral, scale Scale, cl valclass.Class) *big.Int {
	if scale == Full {
		if lit.Scheme == rlwe.BFV {
			return valuation.SNormL1MaxInt()
		}
		return valuation.SNormL1MaxFixed()
	}
	return new(big.Int).Lsh(big.NewInt(int64(cl.M())), uint(cl.XBits))
}

// All returns every entry of a scale: pi_key for the four sets, pi_member
// and pi_eval_c1 for Case 1, pi_enc, pi_eval_c2 and pi_dec for Case 2.
func All(scale Scale) ([]Entry, error) {
	var out []Entry
	for _, lit := range rlwe.Flagship() {
		cl := ClassFor(lit, scale)
		p, err := ParamsFor(lit, scale, cl)
		if err != nil {
			return nil, err
		}
		base := map[string]string{
			"N": fmt.Sprint(p.N()), "J": fmt.Sprint(p.J()), "Q": p.Q().String(),
			"log2_Q": fmt.Sprintf("%.8f", p.LogQ()), "sigma_fl": fmt.Sprint(p.SigmaFl()),
			"B_err": fmt.Sprint(p.BErr()), "scheme": p.Scheme().String(), "case": fmt.Sprint(p.Case()),
		}
		if q := p.QDel(); q != nil {
			base["q_del"] = q.String()
		}
		withClass := func(m map[string]string) map[string]string {
			out := map[string]string{}
			for k, v := range m {
				out[k] = v
			}
			out["class_cols"], out["class_m"] = fmt.Sprint(cl.Cols), fmt.Sprint(cl.M())
			out["w_max"], out["beta"], out["unit"] = fmt.Sprint(cl.WMax), fmt.Sprint(cl.Beta), fmt.Sprint(cl.Unit)
			out["x_bits"], out["f_bits"] = fmt.Sprint(cl.XBits), fmt.Sprint(cl.FBits)
			return out
		}
		clCopy := cl

		kc := keyproof.ConfigFor(p)
		out = append(out, Entry{Circuit: PiKey, Params: lit.Name, Curve: kc.Curve, New: func() frontend.Circuit { return keyproof.New(kc) },
			Constants: withLabel(base, kc.Label), Config: kc, RLWE: p})

		if lit.Case == rlwe.Case1 {
			mc, err := member.ConfigFor(p, cl)
			if err != nil {
				return nil, err
			}
			out = append(out, Entry{Circuit: PiMember, Params: lit.Name, Curve: ecc.BLS12_381, New: func() frontend.Circuit { return member.New(mc) },
				Constants: withClass(base), Config: mc, RLWE: p, Class: &clCopy})
			ec, err := evalc1.ConfigFor(p, cl.M(), cl.XBits, sNormL1(lit, scale, cl))
			if err != nil {
				return nil, err
			}
			out = append(out, Entry{Circuit: PiEvalC1, Params: lit.Name, Curve: ecc.BLS12_381, OnChain: true, New: func() frontend.Circuit { return evalc1.New(ec) },
				Constants: withClass(base), Config: ec, RLWE: p, Class: &clCopy})
			continue
		}
		enc, err := encproof.ConfigFor(p, cl)
		if err != nil {
			return nil, err
		}
		out = append(out, Entry{Circuit: PiEnc, Params: lit.Name, Curve: ecc.BN254, New: func() frontend.Circuit { return encproof.New(enc) },
			Constants: withClass(base), Config: enc, RLWE: p, Class: &clCopy})
		e2, err := evalc2.ConfigFor(p, cl)
		if err != nil {
			return nil, err
		}
		out = append(out, Entry{Circuit: PiEvalC2, Params: lit.Name, Curve: ecc.BN254, New: func() frontend.Circuit { return evalc2.New(e2) },
			Constants: withClass(base), Config: e2, RLWE: p, Class: &clCopy})
		dc, err := decproof.ConfigFor(p)
		if err != nil {
			return nil, err
		}
		out = append(out, Entry{Circuit: PiDec, Params: lit.Name, Curve: ecc.BN254, OnChain: true, New: func() frontend.Circuit { return decproof.New(dc) },
			Constants: base, Config: dc, RLWE: p})
	}
	return out, nil
}

func withLabel(m map[string]string, label string) map[string]string {
	out := map[string]string{"digest_label": label}
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Find returns the entry of a circuit and parameter set.
func Find(scale Scale, circuit, params string) (Entry, error) {
	all, err := All(scale)
	if err != nil {
		return Entry{}, err
	}
	for _, e := range all {
		if e.Circuit == circuit && e.Params == params {
			return e, nil
		}
	}
	return Entry{}, fmt.Errorf("registry: no %s for %s", circuit, params)
}
