// Package se is the witness encryption that makes a proof
// straight-line extractable (option O2).
//
// The setup draws an extraction key pair sk, PK = sk G on the twisted
// Edwards curve embedded in the circuit's field (Jubjub for BLS12-381,
// Baby Jubjub for BN254) and fixes PK in the circuit. The prover picks r
// and shows, besides its relation, that
//
//	R = r G,  K = r PK,  CT_j = m_j + H_dig("se.ks", K.x, K.y, j)
//
// for the packed witness elements m_j, with R and CT public. An extractor
// that holds sk computes K = sk R and reads every m_j from any accepting
// proof without rewinding: knowledge soundness with a straight-line
// extractor under a CRS independent of the simulation CRS, which the
// paper's definition of SE admits (Section 2.2).
package se

import (
	"fmt"
	"io"
	"math/big"

	"fairhe/pkg/hashes"
	"fairhe/pkg/zk/gadgets"

	edbls "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	edbn "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	tw "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
)

// LabelKS is the H_dig label of the keystream.
const LabelKS = "se.ks"

// PublicKey is the extraction key that the setup fixes in a circuit.
type PublicKey struct {
	Field hashes.Field
	X, Y  *big.Int
}

// curveOf returns the twisted Edwards curve embedded in a circuit field.
func curveOf(f hashes.Field) (tw.ID, error) {
	switch f {
	case hashes.BLS12381:
		return tw.BLS12_381, nil
	case hashes.BN254:
		return tw.BN254, nil
	}
	return 0, fmt.Errorf("se: no embedded curve for field %v", f)
}

// Order returns the order of the prime subgroup of the embedded curve.
func Order(f hashes.Field) (*big.Int, error) {
	id, err := curveOf(f)
	if err != nil {
		return nil, err
	}
	p, err := twistededwards.GetCurveParams(id)
	if err != nil {
		return nil, err
	}
	return new(big.Int).Set(p.Order), nil
}

// mul returns the coordinates of s P on the embedded curve of f, with P the
// base point when x and y are nil.
func mul(f hashes.Field, x, y, s *big.Int) (*big.Int, *big.Int, error) {
	switch f {
	case hashes.BLS12381:
		c := edbls.GetEdwardsCurve()
		p := c.Base
		if x != nil {
			p.X.SetBigInt(x)
			p.Y.SetBigInt(y)
		}
		var q edbls.PointAffine
		q.ScalarMultiplication(&p, s)
		return q.X.BigInt(new(big.Int)), q.Y.BigInt(new(big.Int)), nil
	case hashes.BN254:
		c := edbn.GetEdwardsCurve()
		p := c.Base
		if x != nil {
			p.X.SetBigInt(x)
			p.Y.SetBigInt(y)
		}
		var q edbn.PointAffine
		q.ScalarMultiplication(&p, s)
		return q.X.BigInt(new(big.Int)), q.Y.BigInt(new(big.Int)), nil
	}
	return nil, nil, fmt.Errorf("se: no embedded curve for field %v", f)
}

// randScalar draws a uniform scalar below the subgroup order.
func randScalar(f hashes.Field, rng io.Reader) (*big.Int, error) {
	n, err := Order(f)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, (n.BitLen()+7)/8+16) // 128 extra bits: negligible bias
	if _, err := io.ReadFull(rng, buf); err != nil {
		return nil, err
	}
	return new(big.Int).Mod(new(big.Int).SetBytes(buf), n), nil
}

// KeyGen returns the extractor's key sk and the public key PK = sk G.
func KeyGen(f hashes.Field, rng io.Reader) (*big.Int, PublicKey, error) {
	sk, err := randScalar(f, rng)
	if err != nil {
		return nil, PublicKey{}, err
	}
	x, y, err := mul(f, nil, nil, sk)
	return sk, PublicKey{Field: f, X: x, Y: y}, err
}

// keystream returns the j-th keystream element for the shared point K.
func keystream(f hashes.Field, kx, ky *big.Int, j int) (*big.Int, error) {
	return hashes.Dig(f, LabelKS, []*big.Int{kx, ky, big.NewInt(int64(j))})
}

// Encrypt returns R = r G and CT_j = m_j + keystream_j(r PK) for a fresh r,
// with r for the prover's witness.
func Encrypt(pk PublicKey, m []*big.Int, rng io.Reader) (r, rx, ry *big.Int, ct []*big.Int, err error) {
	if r, err = randScalar(pk.Field, rng); err != nil {
		return
	}
	if rx, ry, err = mul(pk.Field, nil, nil, r); err != nil {
		return
	}
	kx, ky, err := mul(pk.Field, pk.X, pk.Y, r)
	if err != nil {
		return
	}
	mod := pk.Field.Modulus()
	for j, v := range m {
		ks, kerr := keystream(pk.Field, kx, ky, j)
		if kerr != nil {
			return nil, nil, nil, nil, kerr
		}
		ct = append(ct, new(big.Int).Mod(new(big.Int).Add(v, ks), mod))
	}
	return
}

// Extract is the extractor: with sk it reads the encrypted witness elements
// from the public R and CT of an accepting proof.
func Extract(f hashes.Field, sk, rx, ry *big.Int, ct []*big.Int) ([]*big.Int, error) {
	kx, ky, err := mul(f, rx, ry, sk)
	if err != nil {
		return nil, err
	}
	mod := f.Modulus()
	out := make([]*big.Int, len(ct))
	for j, c := range ct {
		ks, err := keystream(f, kx, ky, j)
		if err != nil {
			return nil, err
		}
		out[j] = new(big.Int).Mod(new(big.Int).Sub(c, ks), mod)
	}
	return out, nil
}

// EncryptCircuit constrains R = r G, K = r PK and CT_j = m_j +
// keystream_j(K), and returns R and CT.
func EncryptCircuit(api frontend.API, pk PublicKey, r frontend.Variable, m []frontend.Variable) (twistededwards.Point, []frontend.Variable, error) {
	id, err := curveOf(pk.Field)
	if err != nil {
		return twistededwards.Point{}, nil, err
	}
	curve, err := twistededwards.NewEdCurve(api, id)
	if err != nil {
		return twistededwards.Point{}, nil, err
	}
	base := twistededwards.Point{X: curve.Params().Base[0], Y: curve.Params().Base[1]}
	R := curve.ScalarMul(base, r)
	K := curve.ScalarMul(twistededwards.Point{X: pk.X, Y: pk.Y}, r)
	ct := make([]frontend.Variable, len(m))
	for j, v := range m {
		ks, err := gadgets.Digest(api, LabelKS, []frontend.Variable{K.X, K.Y, j})
		if err != nil {
			return twistededwards.Point{}, nil, err
		}
		ct[j] = api.Add(v, ks)
	}
	return R, ct, nil
}
