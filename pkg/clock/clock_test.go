package clock

import (
	"testing"
	"time"
)

// TestResolution: a 2 ms wait reads as 2 ms to within 0.1 ms, and readings
// advance well below a millisecond.
func TestResolution(t *testing.T) {
	start := Now()
	for Since(start) < 2*time.Millisecond {
	}
	if d := Since(start); d < 2*time.Millisecond || d > 2100*time.Microsecond {
		t.Fatalf("2 ms read as %v", d)
	}
	a := Now()
	for Now() == a {
	}
	if d := Since(a); d > 100*time.Microsecond {
		t.Fatalf("the clock advanced by %v", d)
	}
}
