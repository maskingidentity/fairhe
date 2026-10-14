package zkmeasure

import "testing"

func TestMedian(t *testing.T) {
	for _, tc := range []struct {
		xs   []float64
		want float64
	}{{nil, 0}, {[]float64{3}, 3}, {[]float64{5, 1, 3}, 3}, {[]float64{4, 1, 3, 2}, 2.5}} {
		if got := Median(tc.xs); got != tc.want {
			t.Fatalf("Median(%v) = %v, want %v", tc.xs, got, tc.want)
		}
	}
}
