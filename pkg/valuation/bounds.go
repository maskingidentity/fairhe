package valuation

import "math/big"

// Class bounds of the running example (paper Section 3.2 "Sizes" and Appendix
// C.4). They are worst cases over the class, not measurements, and feed the
// flood widths and decoding margins of the parameter sets.

// SNormL1MaxInt bounds ||S||_1 in the integer version by the coarse
// m * n * (2^8 - 1)^2 of Appendix C.4 (< 2^35.1).
func SNormL1MaxInt() *big.Int {
	return big.NewInt(int64(M) * NMax * ValMax * ValMax)
}

// WHatNormL1MaxInt bounds ||w_hat||_1 = (||w||_1 + 2^beta)^2 (< 2^26).
func WHatNormL1MaxInt() *big.Int {
	v := big.NewInt(int64(Cols)*WMax + 1<<Beta)
	return v.Mul(v, v)
}

// FMaxInt bounds the integer output, n (2^beta * 255 + ||w||_1 * 255)^2
// (< 2^52).
func FMaxInt() *big.Int {
	v := big.NewInt(int64(1<<Beta)*ValMax + int64(Cols)*WMax*ValMax)
	v.Mul(v, v)
	return v.Mul(v, big.NewInt(NMax))
}

// SNormL1MaxFixed bounds ||S||_1 in the fixed-point version at its integer
// scale 2^20: the m averages lie in [0, 1], so ||S||_1 <= m 2^20 (< 2^29.1).
func SNormL1MaxFixed() *big.Int {
	return big.NewInt(int64(M) << FracBits)
}

// WHatNormL1MaxFixed bounds ||w_hat||_1 in the fixed-point version at its
// integer scale 2^20: 2^20 (||w||_1 + 1)^2 with ||w||_1 <= 31 * 16 (< 2^38).
func WHatNormL1MaxFixed() *big.Int {
	v := big.NewInt(int64(Cols)*WMaxReal + 1)
	v.Mul(v, v)
	return v.Lsh(v, FracBits)
}

// FMaxFixed bounds the fixed-point output |<w_hat, S>| <= ||w_hat||_1 max|S_k|
// <= (31 * 16 + 1)^2 (< 2^17.92), in real units.
func FMaxFixed() *big.Rat {
	v := big.NewInt(int64(Cols)*WMaxReal + 1)
	return new(big.Rat).SetInt(v.Mul(v, v))
}

// WMaxFixedInt is the bound on the fixed-point weights in units of 2^-10.
const WMaxFixedInt = WMaxReal << WFracBits

// NormL1 returns the l1-norm of an integer vector.
func NormL1(v []int64) *big.Int {
	acc := new(big.Int)
	for _, x := range v {
		if x < 0 {
			x = -x
		}
		acc.Add(acc, big.NewInt(x))
	}
	return acc
}
