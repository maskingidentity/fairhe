package gadgets

import (
	"fmt"
	"math/big"

	"fairhe/pkg/hashes"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/poseidon2"
)

// FieldOf returns the digest field of the circuit's native field.
func FieldOf(api frontend.API) (hashes.Field, error) {
	f := api.Compiler().Field()
	switch {
	case f.Cmp(hashes.BN254.Modulus()) == 0:
		return hashes.BN254, nil
	case f.Cmp(hashes.BLS12381.Modulus()) == 0:
		return hashes.BLS12381, nil
	}
	return 0, fmt.Errorf("gadgets: unsupported field %s", f)
}

// Pack returns the elements e_k = sum_{i<per} v_{k per + i} 2^(bits i), the
// packing of hashes.PackBits (linear, so free); the values must be range
// checked to bits elsewhere for the packing to be injective.
func Pack(api frontend.API, vals []frontend.Variable, bits, per int) []frontend.Variable {
	out := make([]frontend.Variable, 0, (len(vals)+per-1)/per)
	for j := 0; j < len(vals); j += per {
		end := min(j+per, len(vals))
		terms := make([]frontend.Variable, 0, end-j)
		for i := j; i < end; i++ {
			shift := new(big.Int).Lsh(big.NewInt(1), uint(bits*(i-j)))
			terms = append(terms, api.Mul(vals[i], shift))
		}
		out = append(out, sum(api, terms))
	}
	return out
}

// Digest returns H_dig(tag || elems) over the circuit's field with gnark's
// Poseidon2, the counterpart of hashes.Dig: the tag is the constant
// hashes.DigTag(field, label, len(elems)).
func Digest(api frontend.API, label string, elems []frontend.Variable) (frontend.Variable, error) {
	f, err := FieldOf(api)
	if err != nil {
		return nil, err
	}
	h, err := poseidon2.New(api)
	if err != nil {
		return nil, err
	}
	h.Write(hashes.DigTag(f, label, len(elems)))
	h.Write(elems...)
	return h.Sum(), nil
}

// DigestSecret returns the salted digest of a ternary secret, the
// counterpart of hashes.DigSecret: s_i + 1 packed two bits each, then the
// salt element. The coefficients must be constrained ternary elsewhere and
// the salt below 2^128.
func DigestSecret(api frontend.API, label string, s []frontend.Variable, salt frontend.Variable) (frontend.Variable, error) {
	f, err := FieldOf(api)
	if err != nil {
		return nil, err
	}
	shifted := make([]frontend.Variable, len(s))
	for i, x := range s {
		shifted[i] = api.Add(x, 1)
	}
	elems := Pack(api, shifted, 2, hashes.PackPerElement(f, 2))
	return Digest(api, label, append(elems, salt))
}

// Commitment returns the salted hash commitment Com(v) = H_dig(pack(v) ||
// rho) under the label "com." + label, the counterpart of hashes.Commit; the
// values must be range checked to bits elsewhere.
func Commitment(api frontend.API, label string, vals []frontend.Variable, bits int, rho frontend.Variable) (frontend.Variable, error) {
	f, err := FieldOf(api)
	if err != nil {
		return nil, err
	}
	elems := Pack(api, vals, bits, hashes.PackPerElement(f, bits))
	return Digest(api, "com."+label, append(elems, rho))
}
