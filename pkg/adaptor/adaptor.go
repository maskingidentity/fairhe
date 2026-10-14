// Package adaptor implements Schnorr signatures with adaptors on secp256k1
// for the settlement variant without on-chain proof verification (paper
// Appendix B), under a challenge convention that an on-chain verifier can
// check with the ecrecover trick:
//
//	e = keccak256( Px (32B) || yParity(P) (1B) || addr(R) (20B) || m (32B) ) mod n
//
// Plain signature: sigma = (R, s) with R = rho*G, s = rho + e*d mod n;
// verification is s*G == R + e*P. Adaptor pre-signature for a statement
// K = k*G: R = rho*G + K, shat = rho + e*d mod n; pre-verification is
// shat*G == (R - K) + e*P. Adapt adds the witness (s = shat + k), Extract
// recovers it (k = s - shat), which is the atomicity lever of the protocol:
// the on-chain claim(sigma) reveals s, and the buyer extracts k off-chain.
//
// Curve backend: github.com/decred/dcrd/dcrec/secp256k1/v4. This is the
// module that btcec/v2 v2.5.0 wraps with pure type aliases (btcec's
// PrivateKey, PublicKey, JacobianPoint, ModNScalar and FieldVal are all
// `type X = secp.X`), so every exported signature below is type-identical
// to the btcec/v2 API.
package adaptor

import (
	"errors"
	"math/big"

	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

// Point is the affine curve point type used across the protocol. It is the
// same type as *btcec.PublicKey (alias chain btcec/v2 -> decred secp256k1/v4).
type Point = secp.PublicKey

// PrivateKey mirrors *btcec.PrivateKey through the same alias chain.
type PrivateKey = secp.PrivateKey

// n is the secp256k1 group order (read-only; never mutated).
var n = secp.Params().N

// Sig is a plain Schnorr signature sigma = (R, s).
type Sig struct {
	R *Point
	S *big.Int
}

// PreSig is an adaptor pre-signature sigmaHat = (R, shat) for some statement
// K; R already includes K (R = rho*G + K), so R is what the challenge — and
// later the on-chain verifier — binds to.
type PreSig struct {
	R    *Point
	Shat *big.Int
}

// keccak256 hashes the concatenation of the given byte slices with the
// legacy (Ethereum) Keccak-256.
func keccak256(parts ...[]byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// AddrOfPoint returns the Ethereum-style address of a point: the last 20
// bytes of keccak256(X||Y) over the 64-byte uncompressed coordinates
// (no 0x04 prefix). This is what ecrecover returns on-chain.
func AddrOfPoint(p *Point) [20]byte {
	unc := p.SerializeUncompressed() // 0x04 || X (32B) || Y (32B)
	h := keccak256(unc[1:])
	var a [20]byte
	copy(a[:], h[12:])
	return a
}

// PxBytes returns the 32-byte big-endian X coordinate of a point (on-chain
// verifier input r = Px).
func PxBytes(p *Point) [32]byte {
	var b [32]byte
	copy(b[:], p.SerializeUncompressed()[1:33])
	return b
}

// YParity returns 0 if the Y coordinate of p is even and 1 otherwise
// (on-chain verifier input v = 27 + yParity(P)).
func YParity(p *Point) byte {
	return p.SerializeUncompressed()[64] & 1
}

// Scalar32 returns the canonical 32-byte big-endian encoding of a scalar
// mod n (on-chain verifier inputs s and e).
func Scalar32(x *big.Int) [32]byte {
	var b [32]byte
	new(big.Int).Mod(x, n).FillBytes(b[:])
	return b
}

// SBytes returns the 32-byte encoding of s for the on-chain verifier.
func (s Sig) SBytes() [32]byte { return Scalar32(s.S) }

// AddrR returns addr(R), the value the on-chain verifier compares the
// ecrecover output against.
func (s Sig) AddrR() [20]byte { return AddrOfPoint(s.R) }

// ShatBytes returns the 32-byte encoding of shat.
func (p PreSig) ShatBytes() [32]byte { return Scalar32(p.Shat) }

// AddrR returns addr(R) of the pre-signature (same R as the adapted sigma).
func (p PreSig) AddrR() [20]byte { return AddrOfPoint(p.R) }

// Challenge computes e = keccak256(Px || yParity(P) || addr(R) || m) mod n.
// m is a 32-byte message digest; addrR is addr(R) so that the challenge binds
// exactly what the on-chain ecrecover check reconstructs.
func Challenge(P *Point, addrR [20]byte, m [32]byte) *big.Int {
	px := PxBytes(P)
	buf := make([]byte, 0, 85)
	buf = append(buf, px[:]...)
	buf = append(buf, YParity(P))
	buf = append(buf, addrR[:]...)
	buf = append(buf, m[:]...)
	h := keccak256(buf)
	e := new(big.Int).SetBytes(h[:])
	return e.Mod(e, n)
}

// EBytes is the 32-byte challenge, ready for the on-chain verifier
// (z = n - e*Px mod n is computed in Solidity from this value).
func EBytes(P *Point, addrR [20]byte, m [32]byte) [32]byte {
	return Scalar32(Challenge(P, addrR, m))
}

// --- scalar / point helpers -------------------------------------------------

// scalarInt converts a private key to its scalar as a big.Int in [1, n).
func scalarInt(d *PrivateKey) *big.Int {
	return new(big.Int).SetBytes(d.Serialize())
}

// toModN converts x mod n into the constant-time scalar representation used
// by the decred point arithmetic.
func toModN(x *big.Int) *secp.ModNScalar {
	var b [32]byte
	new(big.Int).Mod(x, n).FillBytes(b[:])
	var s secp.ModNScalar
	s.SetBytes(&b) // cannot overflow: already reduced mod n
	return &s
}

// mulG sets result = x*G.
func mulG(x *big.Int, result *secp.JacobianPoint) {
	secp.ScalarBaseMultNonConst(toModN(x), result)
}

// mulPoint sets result = x*P.
func mulPoint(x *big.Int, P *Point, result *secp.JacobianPoint) {
	var j secp.JacobianPoint
	P.AsJacobian(&j)
	secp.ScalarMultNonConst(toModN(x), &j, result)
}

// negJacobian negates a Jacobian point in place.
func negJacobian(j *secp.JacobianPoint) {
	j.Y.Normalize().Negate(1).Normalize()
}

// KeyGen samples d in [1, n) and P = d*G. It resamples in the (probability
// ~2^-128) case Px >= n, because the on-chain verifier requires Px < n to use
// Px as the ecrecover r value.
func KeyGen() (*PrivateKey, *Point, error) {
	for {
		d, err := secp.GeneratePrivateKey()
		if err != nil {
			return nil, nil, err
		}
		P := d.PubKey()
		if P.X().Cmp(n) < 0 {
			return d, P, nil
		}
	}
}

// Sign produces a plain Schnorr signature on the 32-byte digest m.
func Sign(d *PrivateKey, m [32]byte) (Sig, error) {
	if d == nil {
		return Sig{}, errors.New("adaptor: nil private key")
	}
	rho, err := secp.GeneratePrivateKey() // uniform nonce in [1, n)
	if err != nil {
		return Sig{}, err
	}
	R := rho.PubKey()
	e := Challenge(d.PubKey(), AddrOfPoint(R), m)
	s := new(big.Int).Mul(e, scalarInt(d))
	s.Add(s, scalarInt(rho))
	s.Mod(s, n)
	rho.Zero()
	return Sig{R: R, S: s}, nil
}

// Verify checks s*G == R + e*P.
func Verify(P *Point, m [32]byte, sig Sig) bool {
	if P == nil || sig.R == nil || sig.S == nil {
		return false
	}
	if sig.S.Sign() < 0 || sig.S.Cmp(n) >= 0 {
		return false
	}
	e := Challenge(P, AddrOfPoint(sig.R), m)
	var lhs secp.JacobianPoint
	mulG(sig.S, &lhs)
	var jR, eP, rhs secp.JacobianPoint
	sig.R.AsJacobian(&jR)
	mulPoint(e, P, &eP)
	secp.AddNonConst(&jR, &eP, &rhs)
	return lhs.EquivalentNonConst(&rhs)
}

// NewWitness samples a fresh adaptor witness k in [1, n) with statement
// K = k*G. In the protocol the seller samples it per session (single use).
func NewWitness() (*big.Int, *Point, error) {
	kp, err := secp.GeneratePrivateKey()
	if err != nil {
		return nil, nil, err
	}
	k := new(big.Int).SetBytes(kp.Serialize())
	K := kp.PubKey()
	kp.Zero()
	return k, K, nil
}

// PreSign produces an adaptor pre-signature on m for the statement K:
// R = rho*G + K, shat = rho + e*d mod n with e bound to the combined R.
func PreSign(d *PrivateKey, m [32]byte, K *Point) (PreSig, error) {
	if d == nil || K == nil {
		return PreSig{}, errors.New("adaptor: nil key or statement")
	}
	for {
		rho, err := secp.GeneratePrivateKey()
		if err != nil {
			return PreSig{}, err
		}
		var jRhat, jK, jR secp.JacobianPoint
		mulG(scalarInt(rho), &jRhat)
		K.AsJacobian(&jK)
		secp.AddNonConst(&jRhat, &jK, &jR)
		if jR.Z.IsZero() {
			// K == -Rhat: R would be the point at infinity; resample rho.
			continue
		}
		jR.ToAffine()
		R := secp.NewPublicKey(&jR.X, &jR.Y)
		e := Challenge(d.PubKey(), AddrOfPoint(R), m)
		shat := new(big.Int).Mul(e, scalarInt(d))
		shat.Add(shat, scalarInt(rho))
		shat.Mod(shat, n)
		rho.Zero()
		return PreSig{R: R, Shat: shat}, nil
	}
}

// VerifyPreSig checks shat*G == (R - K) + e*P. A pre-signature that passes
// this check adapts, with the witness of K, into a signature Verify accepts
// (property (ii)); it does not itself satisfy Verify because of
// the K offset (property (i)).
func VerifyPreSig(P *Point, m [32]byte, K *Point, ps PreSig) bool {
	if P == nil || K == nil || ps.R == nil || ps.Shat == nil {
		return false
	}
	if ps.Shat.Sign() < 0 || ps.Shat.Cmp(n) >= 0 {
		return false
	}
	e := Challenge(P, AddrOfPoint(ps.R), m)
	var lhs secp.JacobianPoint
	mulG(ps.Shat, &lhs)
	var jR, jK, RminusK, eP, rhs secp.JacobianPoint
	ps.R.AsJacobian(&jR)
	K.AsJacobian(&jK)
	negJacobian(&jK)
	secp.AddNonConst(&jR, &jK, &RminusK)
	mulPoint(e, P, &eP)
	secp.AddNonConst(&RminusK, &eP, &rhs)
	return lhs.EquivalentNonConst(&rhs)
}

// Adapt completes a pre-signature with the witness: s = shat + k mod n.
// The result is a plain signature iff k is the witness of the K used in
// PreSign (properties (ii)/(iv)).
func Adapt(ps PreSig, k *big.Int) Sig {
	s := new(big.Int).Add(ps.Shat, k)
	s.Mod(s, n)
	return Sig{R: ps.R, S: s}
}

// Extract recovers the witness from a pre-signature and its adapted
// signature: k = s - shat mod n. In the protocol the buyer runs this on the
// sigma revealed by the on-chain claim event.
func Extract(ps PreSig, sig Sig) *big.Int {
	k := new(big.Int).Sub(sig.S, ps.Shat)
	return k.Mod(k, n)
}
