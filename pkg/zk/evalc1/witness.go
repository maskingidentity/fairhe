package evalc1

import (
	"fmt"
	"math/big"

	"fairhe/pkg/hashes"
	"fairhe/pkg/rlwe"
	"fairhe/pkg/zk/gadgets"
)

// ConfigFor returns the configuration of a Case 1 parameter set for a class
// with m entries released at coefficient m - 1, entries of xBits bits (at
// most xMax if it is not nil), and the class bound sNormL1 on ||S_bar||_1
// at the plaintext scale.
func ConfigFor(p *rlwe.Params, m, xBits int, xMax, sNormL1 *big.Int) (Config, error) {
	if p.Case() != rlwe.Case1 {
		return Config{}, fmt.Errorf("evalc1: parameters of case %d", p.Case())
	}
	q, qdel := p.Q(), p.QDel()
	dBits := new(big.Int).Sub(qdel, big.NewInt(1)).BitLen()
	lb := new(big.Int).Add(sNormL1, big.NewInt(int64(p.N()+2)))
	return Config{
		N: p.N(), M: m, J: p.J(), Q: q, QDel: qdel,
		QBits:   new(big.Int).Sub(q, big.NewInt(1)).BitLen(),
		DBits:   dBits,
		DPer:    hashes.PackPerElement(hashes.BLS12381, dBits),
		XBits:   xBits,
		XMax:    xMax,
		PtScale: p.PtScale(),
		BErr:    int64(p.BErr()),
		SigmaFl: p.SigmaFl(),
		LBound:  lb,
	}, nil
}

// Inputs are the values of one Case 1 claim: the order's ciphertext, the
// buyer's key, the seller's data and salt, the witnesses that the rlwe
// Case 1 path exported, and the blob evaluation point.
type Inputs struct {
	Params  *rlwe.Params
	OrderID *big.Int
	PK      *rlwe.PublicKey
	C       *rlwe.Ciphertext
	X       []int64 // S, M entries
	Rho     []byte
	San     *rlwe.SanitizeWitness
	Del     *rlwe.Deliverable
	Sw      *rlwe.SwitchWitness
	Z       *big.Int
}

// Public holds the public inputs as the contract and the seller see them.
type Public struct {
	OrderID, HC, HPk, ComX, HD, Z, YZ *big.Int
	Elems                             []*big.Int // the blob's leading elements
}

// BlobElements returns the deliverable packed for the blob:
// D_0, D_1[0], ..., D_1[N-1], DPer coefficients per element.
func BlobElements(cfg Config, d *rlwe.Deliverable) ([]*big.Int, error) {
	all := append([]*big.Int{d.D0}, d.D1...)
	return hashes.PackBits(hashes.BLS12381, all, cfg.DBits)
}

// PublicDigests computes h_c and h_pk natively, as the buyer and the
// contract record them.
func PublicDigests(cfg Config, p *rlwe.Params, c *rlwe.Ciphertext, pk *rlwe.PublicKey) (hc, hpk *big.Int, err error) {
	hc, err = hashes.DigPoly(hashes.BLS12381, LabelHC, append(p.ToBig(c.C0), p.ToBig(c.C1)...), cfg.QBits)
	if err != nil {
		return nil, nil, err
	}
	hpk, err = hashes.DigPoly(hashes.BLS12381, LabelHPk, append(p.ToBig(pk.B), p.ToBig(pk.A)...), cfg.QBits)
	return hc, hpk, err
}

// Assign builds the full assignment and the public inputs.
func Assign(cfg Config, in *Inputs) (*Circuit, *Public, error) {
	p := in.Params
	n, q, qdel := cfg.N, cfg.Q, cfg.QDel
	if len(in.X) != cfg.M {
		return nil, nil, fmt.Errorf("evalc1: %d data entries, want %d", len(in.X), cfg.M)
	}
	c0, c1 := p.ToBig(in.C.C0), p.ToBig(in.C.C1)
	b, a := p.ToBig(in.PK.B), p.ToBig(in.PK.A)
	hc, hpk, err := PublicDigests(cfg, p, in.C, in.PK)
	if err != nil {
		return nil, nil, err
	}
	xs := gadgets.Ints(in.X)
	comX, err := hashes.Commit(hashes.BLS12381, LabelX, xs, cfg.XBits, in.Rho)
	if err != nil {
		return nil, nil, err
	}

	// S_bar as a dense polynomial at the plaintext scale.
	sbar := make([]*big.Int, n)
	for i := range sbar {
		sbar[i] = new(big.Int)
	}
	for k, x := range in.X {
		sbar[cfg.M-1-k] = big.NewInt(x * cfg.PtScale)
	}
	cs1 := in.Sw.C1
	L, K, err := gadgets.Quotients(n, q,
		[]gadgets.WTerm{{A: c1, B: sbar}, {A: a, B: gadgets.Ints(in.San.V)}},
		[][]*big.Int{gadgets.Ints(in.San.E1)}, [][]*big.Int{cs1})
	if err != nil {
		return nil, nil, fmt.Errorf("evalc1: product identity: %w", err)
	}

	// Released coefficient of the first component and its quotient.
	inner := new(big.Int)
	for k := range in.X {
		idx := cfg.J - (cfg.M - 1 - k)
		t := new(big.Int).Mul(sbar[cfg.M-1-k], c0[(idx+n)%n])
		if idx < 0 {
			t.Neg(t)
		}
		inner.Add(inner, t)
	}
	bv := negacyclicCoeff(b, in.San.V, cfg.J)
	num := new(big.Int).Add(inner, bv)
	num.Add(num, big.NewInt(in.San.E0[cfg.J])).Add(num, in.San.EFl).Sub(num, in.Sw.C0J)
	ell0, rem := new(big.Int).QuoRem(num, q, new(big.Int))
	if rem.Sign() != 0 {
		return nil, nil, fmt.Errorf("evalc1: released coefficient is not the sanitised value")
	}

	// Switch witnesses.
	D := append([]*big.Int{in.Del.D0}, in.Del.D1...)
	R := append([]*big.Int{in.Sw.R0}, in.Sw.R1...)
	cs := append([]*big.Int{in.Sw.C0J}, cs1...)
	W := make([]*big.Int, n+1)
	for j := range W {
		tilde := new(big.Int).Mul(qdel, cs[j])
		tilde.Add(tilde, R[j]).Quo(tilde, q)
		W[j] = new(big.Int).Sub(tilde, D[j])
		W[j].Quo(W[j], qdel)
		if W[j].Sign() < 0 || W[j].Cmp(big.NewInt(1)) > 0 {
			return nil, nil, fmt.Errorf("evalc1: switch of coefficient %d is not a rounding", j)
		}
	}

	elems, err := BlobElements(cfg, in.Del)
	if err != nil {
		return nil, nil, err
	}
	hd, err := hashes.Dig(hashes.BLS12381, LabelHD, elems)
	if err != nil {
		return nil, nil, err
	}
	yz, err := gadgets.BlobEvalNative(elems, in.Z)
	if err != nil {
		return nil, nil, err
	}

	w := New(cfg)
	w.OrderID, w.HC, w.HPk, w.ComX, w.HD, w.Z, w.YZ = in.OrderID, hc, hpk, comX, hd, in.Z, yz
	for i := 0; i < n; i++ {
		w.C0[i], w.C1[i], w.B[i], w.A[i] = c0[i], c1[i], b[i], a[i]
		w.V[i], w.E0[i], w.E1[i] = in.San.V[i], in.San.E0[i], in.San.E1[i]
		w.CS1[i], w.L[i], w.K[i] = cs1[i], L[i], K[i]
	}
	for k, x := range xs {
		w.X[k] = x
	}
	w.Rho = new(big.Int).SetBytes(in.Rho)
	w.EFl, w.CS0J, w.Ell0 = in.San.EFl, in.Sw.C0J, ell0
	for j := 0; j <= n; j++ {
		w.D[j], w.W[j], w.R[j] = D[j], W[j], R[j]
	}
	pub := &Public{OrderID: in.OrderID, HC: hc, HPk: hpk, ComX: comX, HD: hd, Z: in.Z, YZ: yz, Elems: elems}
	return w, pub, nil
}

// negacyclicCoeff returns coefficient j of a s modulo X^N + 1 over Z.
func negacyclicCoeff(a []*big.Int, s []int64, j int) *big.Int {
	n := len(a)
	acc := new(big.Int)
	t := new(big.Int)
	for i := 0; i < n; i++ {
		k, sign := j-i, int64(1)
		if k < 0 {
			k, sign = k+n, -1
		}
		if s[k] != 0 {
			acc.Add(acc, t.Mul(a[i], big.NewInt(sign*s[k])))
		}
	}
	return acc
}
