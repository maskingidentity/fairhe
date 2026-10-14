package rlwe

import "math/big"

// The four parameter sets of the running example (Table 2), instantiated
// with explicit chains of NTT-friendly primes (q_i = 1 mod 2^14), each the
// largest such prime below its power of two, so that log2 Q equals the bit
// length of Table 2 and the margins of Appendix C.4 hold (TestMargins).
//
//	setting      chain (bits)        log2 Q        q_del          sigma_fl
//	Case 1 BFV   45, 45, 44          133.99999995  68-bit prime   79
//	Case 1 CKKS  43 (= q_del), 60    102.99999997  first prime    73
//	Case 2 BFV   42, 42, 41          124.99999958  -              70
//	Case 2 CKKS  56, 55              110.99999999  -              82
//
// In Case 1 CKKS the delivery modulus is the first prime of the chain, so
// Q / q_del is the 60-bit prime (< 2^60.99) and the switch from Q to q_del is
// the rounded division by the last prime.

const (
	logN    = 13
	bErr    = 19  // 6-sigma tail of the discrete Gaussian with sigma = 3.2
	sigma   = 3.2 // standard deviation of the error distribution
	lambdaS = 40  // statistical security of the flood
	jOut    = 527 // released coefficient m - 1 of the running example
)

// qDelCase1BFV is the largest prime below 2^68 that is 1 mod 2^14 (>= 2^67.5).
var qDelCase1BFV, _ = new(big.Int).SetString("295147905179352727553", 10)

// Case1BFV returns the Case 1 BFV parameters: t = 2^53, sigma_fl = 79.
func Case1BFV() ParamsLiteral {
	return ParamsLiteral{
		Name: "case1_bfv", Scheme: BFV, Case: Case1, LogN: logN,
		Q:    []uint64{35184371613697, 35184371417089, 17592186028033},
		LogT: 53, QDel: new(big.Int).Set(qDelCase1BFV),
		SigmaFl: 79, BErr: bErr, Sigma: sigma, LambdaS: lambdaS, J: jOut,
		PaperLogQMin: 133.63, PaperLogQDelMin: 67.5,
	}
}

// Case1CKKS returns the Case 1 CKKS parameters: weights encrypted at scale
// 2^64, statistics multiplied at 2^20, sigma_fl = 73, 43-bit q_del,
// tau < 2^-10.
func Case1CKKS() ParamsLiteral {
	const qDel = 8796092858369 // largest prime below 2^43 that is 1 mod 2^14
	return ParamsLiteral{
		Name: "case1_ckks", Scheme: CKKS, Case: Case1, LogN: logN,
		Q:           []uint64{qDel, 1152921504606830593},
		LogScaleEnc: 64, LogScalePt: 20, FracBits: 20,
		QDel:    new(big.Int).SetUint64(qDel),
		SigmaFl: 73, BErr: bErr, Sigma: sigma, LambdaS: lambdaS, J: jOut,
		PaperLogQMin: 102.92, PaperLogQOverQDelMax: 60.99, LogTauMax: -10,
	}
}

// Case2BFV returns the Case 2 BFV parameters: t = 2^53, sigma_fl = 70.
func Case2BFV() ParamsLiteral {
	return ParamsLiteral{
		Name: "case2_bfv", Scheme: BFV, Case: Case2, LogN: logN,
		Q:       []uint64{4398046150657, 4398045708289, 2199023190017},
		LogT:    53,
		SigmaFl: 70, BErr: bErr, Sigma: sigma, LambdaS: lambdaS, J: jOut,
		PaperLogQMin: 124, PaperLogQStrict: true,
	}
}

// Case2CKKS returns the Case 2 CKKS parameters: statistics encrypted at
// scale 2^72, weights multiplied at 2^20, sigma_fl = 82, tau ~ 2^-10.
func Case2CKKS() ParamsLiteral {
	return ParamsLiteral{
		Name: "case2_ckks", Scheme: CKKS, Case: Case2, LogN: logN,
		Q:           []uint64{72057594037616641, 36028797018652673},
		LogScaleEnc: 72, LogScalePt: 20, FracBits: 20,
		SigmaFl: 82, BErr: bErr, Sigma: sigma, LambdaS: lambdaS, J: jOut,
		// Table 2 states tau ~ 2^-10: the flood alone contributes exactly
		// 2^-10 and the noise adds 2^-49.8.
		PaperLogQMin: 110.92, LogTauMax: -9.999,
	}
}

// Flagship returns the four literals in the column order of Table 2.
func Flagship() []ParamsLiteral {
	return []ParamsLiteral{Case1BFV(), Case1CKKS(), Case2BFV(), Case2CKKS()}
}
