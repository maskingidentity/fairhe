// Package valuation implements the running example of the paper
// (Section 3.2): pre-purchase valuation of a dataset by the squared error of
// the buyer's linear model,
//
//	f_w = ||2^beta y - Z w||_2^2 = <w_hat, S>,
//
// with the sufficient statistics S = (Z^T Z, Z^T y, y^T y) of the seller's
// records and the expanded weights w_hat of the buyer. The package has two
// versions of the class: an integer one for BFV (8-bit features, targets and
// weights, beta = 12) and a fixed-point one for CKKS (features and targets in
// [0, 1], statistics as averages in 2^-20 Z, weights in 2^-10 Z with
// |w_j| <= 16, beta = 0). It has no dependency on the HE code: it produces the
// integer message vectors, their coefficient encodings and the class bounds
// that the parameter margins use.
package valuation

import (
	"fmt"
	"math/big"
	"math/rand/v2"
)

// Class constants of the running example.
const (
	D    = 30                         // features per record
	Cols = D + 1                      // columns of Z: the features and a constant 1
	M    = Cols*(Cols+1)/2 + Cols + 1 // entries of S and w_hat (528)
	J    = M - 1                      // coefficient that holds the output (527)

	NMax    = 1 << 10 // records
	ValMax  = 255     // features and targets in [0, 255]
	WMax    = 1 << 7  // integer weights: |w_j| <= 128
	Beta    = 12      // public shift of the target (integer version)
	nOffDia = Cols * (Cols - 1) / 2

	// Fixed-point (CKKS) version.
	FracBits  = 20 // statistics and expanded weights in units of 2^-20
	WFracBits = 10 // weights in units of 2^-10
	WMaxReal  = 16 // |w_j| <= 16, i.e. |w_int| <= 16 * 2^10
)

// Dataset is the seller's data: n records of Cols integer columns (the
// features in [0, 255] followed by the constant 1) and n targets in [0, 255].
// The fixed-point version reads every feature and target as v/255.
type Dataset struct {
	Z [][]int64
	Y []int64
}

// N returns the number of records.
func (ds *Dataset) N() int { return len(ds.Y) }

// Generate returns a dataset of n records from a fixed seed. Targets follow
// a planted convex combination of the features plus noise, so that a fitted
// linear model has a small error.
func Generate(seed uint64, n int) *Dataset {
	if n < 1 || n > NMax {
		panic(fmt.Sprintf("valuation: n = %d outside [1, %d]", n, NMax))
	}
	rng := rand.New(rand.NewPCG(seed, 0x76616c75))
	coef := make([]float64, D)
	sum := 0.0
	for j := range coef {
		coef[j] = rng.Float64()
		sum += coef[j]
	}
	ds := &Dataset{Z: make([][]int64, n), Y: make([]int64, n)}
	for i := 0; i < n; i++ {
		row := make([]int64, Cols)
		y := 0.0
		for j := 0; j < D; j++ {
			row[j] = rng.Int64N(ValMax + 1)
			y += coef[j] / sum * float64(row[j])
		}
		row[D] = 1
		ds.Z[i] = row
		ds.Y[i] = clamp(int64(y+8*rng.NormFloat64()+0.5), 0, ValMax)
	}
	return ds
}

// WorstCase returns the dataset that maximises every statistic: NMax records
// with every feature and target at 255.
func WorstCase() *Dataset {
	ds := &Dataset{Z: make([][]int64, NMax), Y: make([]int64, NMax)}
	for i := range ds.Y {
		row := make([]int64, Cols)
		for j := 0; j < D; j++ {
			row[j] = ValMax
		}
		row[D] = 1
		ds.Z[i] = row
		ds.Y[i] = ValMax
	}
	return ds
}

// Weights are Cols signed integers: |w_j| <= WMax in the integer version, and
// fixed-point values w_j = w_int / 2^10 with |w_int| <= 16 * 2^10 in the CKKS
// version.
type Weights []int64

// RandomWeights draws weights uniformly from the class [-max, max]^Cols.
func RandomWeights(seed uint64, max int64) Weights {
	rng := rand.New(rand.NewPCG(seed, 0x77656967))
	w := make(Weights, Cols)
	for j := range w {
		w[j] = rng.Int64N(2*max+1) - max
	}
	return w
}

// WorstWeights returns the weights with |w_j| = max that maximise both the
// l1-norm of w_hat and, on the worst-case data, the output: w_j = -max.
func WorstWeights(max int64) Weights {
	w := make(Weights, Cols)
	for j := range w {
		w[j] = -max
	}
	return w
}

// statIndex enumerates S and w_hat in one fixed order:
// the diagonal (j, j) for j < Cols, the strict upper triangle (j, k) for
// j < k in lexicographic order, then Z^T y for each column, then y^T y.
// pairs returns the (j, k) column pairs of the first two blocks.
func pairs() [][2]int {
	ps := make([][2]int, 0, Cols+nOffDia)
	for j := 0; j < Cols; j++ {
		ps = append(ps, [2]int{j, j})
	}
	for j := 0; j < Cols; j++ {
		for k := j + 1; k < Cols; k++ {
			ps = append(ps, [2]int{j, k})
		}
	}
	return ps
}

// Stats returns the integer statistics S of the BFV version, in the order of
// w_hat: (sum_i z_ij^2)_j, (sum_i z_ij z_ik)_{j<k}, (sum_i z_ij y_i)_j,
// sum_i y_i^2. Every entry is below 2^26.
func Stats(ds *Dataset) []int64 {
	S := make([]int64, 0, M)
	for _, p := range pairs() {
		var s int64
		for i := range ds.Y {
			s += ds.Z[i][p[0]] * ds.Z[i][p[1]]
		}
		S = append(S, s)
	}
	for j := 0; j < Cols; j++ {
		var s int64
		for i := range ds.Y {
			s += ds.Z[i][j] * ds.Y[i]
		}
		S = append(S, s)
	}
	var s int64
	for _, y := range ds.Y {
		s += y * y
	}
	return append(S, s)
}

// ExpandWeights returns the integer expanded weights of the BFV version,
// w_hat = ((w_j^2)_j, (2 w_j w_k)_{j<k}, (-2^(beta+1) w_j)_j, 2^(2 beta)).
func ExpandWeights(w Weights) []int64 {
	return expand(w, Beta, 1)
}

// expand computes w_hat with shift beta; unit is the factor applied to the
// linear block's scale (1 in the integer version, 2^10 in the fixed-point
// version, see ExpandWeightsFixed).
func expand(w Weights, beta int, unit int64) []int64 {
	checkWeights(w)
	out := make([]int64, 0, M)
	for _, p := range pairs() {
		if p[0] == p[1] {
			out = append(out, w[p[0]]*w[p[0]])
		} else {
			out = append(out, 2*w[p[0]]*w[p[1]])
		}
	}
	for j := 0; j < Cols; j++ {
		out = append(out, -(int64(1)<<(beta+1))*w[j]*unit)
	}
	return append(out, (int64(1)<<(2*beta))*unit*unit)
}

// F returns f_w = ||2^beta y - Z w||_2^2 of the integer version, computed
// from the records (not from S), as the reference value.
func F(ds *Dataset, w Weights) *big.Int {
	checkWeights(w)
	f := new(big.Int)
	r := new(big.Int)
	for i, row := range ds.Z {
		v := ds.Y[i] << Beta
		for j, z := range row {
			v -= z * w[j]
		}
		r.SetInt64(v)
		f.Add(f, r.Mul(r, r))
	}
	return f
}

// InnerProduct returns <a, b> over the integers.
func InnerProduct(a, b []int64) *big.Int {
	if len(a) != len(b) {
		panic("valuation: inner product of vectors of different lengths")
	}
	acc := new(big.Int)
	t := new(big.Int)
	for i := range a {
		acc.Add(acc, t.Mul(big.NewInt(a[i]), big.NewInt(b[i])))
	}
	return acc
}

// StatsFixed returns the statistics of the fixed-point version as integers
// in units of 2^-20: the averages over the records of the products of the
// real columns (features v/255, the constant 1, targets v/255), each rounded
// to the nearest multiple of 2^-20. Every entry lies in [0, 2^20].
func StatsFixed(ds *Dataset) []int64 {
	n := int64(ds.N())
	col := func(i, j int) (num, den int64) { // real value of column j of record i
		if j == D {
			return 1, 1
		}
		return ds.Z[i][j], ValMax
	}
	avg := func(prod func(i int) (num, den int64)) int64 {
		acc := new(big.Rat)
		for i := range ds.Y {
			num, den := prod(i)
			acc.Add(acc, big.NewRat(num, den))
		}
		acc.Quo(acc, new(big.Rat).SetInt64(n))
		return roundRat(acc.Mul(acc, new(big.Rat).SetInt64(1<<FracBits)))
	}
	S := make([]int64, 0, M)
	for _, p := range pairs() {
		S = append(S, avg(func(i int) (int64, int64) {
			a, da := col(i, p[0])
			b, db := col(i, p[1])
			return a * b, da * db
		}))
	}
	for j := 0; j < Cols; j++ {
		S = append(S, avg(func(i int) (int64, int64) {
			a, da := col(i, j)
			return a * ds.Y[i], da * ValMax
		}))
	}
	return append(S, avg(func(i int) (int64, int64) {
		return ds.Y[i] * ds.Y[i], ValMax * ValMax
	}))
}

// ExpandWeightsFixed returns the expanded weights of the fixed-point version
// (beta = 0) in units of 2^-20, for weights w_int in units of 2^-10:
// (w_int_j^2, 2 w_int_j w_int_k, -2 * 2^10 * w_int_j, 2^20).
func ExpandWeightsFixed(w Weights) []int64 {
	return expand(w, 0, 1<<WFracBits)
}

// FFixed returns the fixed-point output on the committed statistics,
// <w_hat, S> * 2^-40, exactly. It differs from the mean squared error of the
// unrounded averages by the rounding of S to 2^-20 Z.
func FFixed(S []int64, w Weights) *big.Rat {
	ip := InnerProduct(ExpandWeightsFixed(w), S)
	return new(big.Rat).SetFrac(ip, new(big.Int).Lsh(big.NewInt(1), 2*FracBits))
}

// MSE returns the mean squared error of the fixed-point model on the
// records, without any rounding of the statistics (a reference value).
func MSE(ds *Dataset, w Weights) *big.Rat {
	acc := new(big.Rat)
	for i, row := range ds.Z {
		r := big.NewRat(ds.Y[i], ValMax)
		for j, z := range row {
			x := big.NewRat(z, ValMax)
			if j == D {
				x.SetInt64(1)
			}
			r.Sub(r, x.Mul(x, big.NewRat(w[j], 1<<WFracBits)))
		}
		acc.Add(acc, r.Mul(r, r))
	}
	return acc.Quo(acc, new(big.Rat).SetInt64(int64(ds.N())))
}

// EncodeForward returns the coefficient encoding v(X) = sum_k v_k X^k as a
// coefficient vector of length n (the ring degree).
func EncodeForward(v []int64, n int) []int64 {
	if len(v) > n {
		panic("valuation: vector longer than the ring degree")
	}
	out := make([]int64, n)
	copy(out, v)
	return out
}

// EncodeReversed returns the reversed encoding v_bar(X) = sum_k v_k X^(M-1-k),
// so that coefficient M-1 of w_hat(X) * S_bar(X) is <w_hat, S>.
func EncodeReversed(v []int64, n int) []int64 {
	if len(v) != M || 2*M-1 > n {
		panic("valuation: reversed encoding needs |v| = M and 2M-1 <= N")
	}
	out := make([]int64, n)
	for k, x := range v {
		out[M-1-k] = x
	}
	return out
}

func checkWeights(w Weights) {
	if len(w) != Cols {
		panic(fmt.Sprintf("valuation: %d weights, want %d", len(w), Cols))
	}
}

func clamp(v, lo, hi int64) int64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// roundRat rounds a non-negative rational to the nearest integer (halves up).
func roundRat(r *big.Rat) int64 {
	num := new(big.Int).Mul(r.Num(), big.NewInt(2))
	num.Add(num, r.Denom())
	den := new(big.Int).Mul(r.Denom(), big.NewInt(2))
	return num.Quo(num, den).Int64()
}
