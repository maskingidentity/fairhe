// Package clock is the monotonic clock of the measurements. On Windows,
// Go's time.Now advances with the system timer interrupt, whose period (0.5
// to 15.6 ms) is set by whichever process asks for the finest, so a step of
// a few milliseconds reads as zero or as a whole tick; the measurements read
// the performance counter there instead (100 ns ticks). Elsewhere the clock
// is time.Now.
package clock

import "time"

// Reading is a monotonic clock reading.
type Reading int64

// Now returns the current reading.
func Now() Reading { return now() }

// Since returns the time elapsed since r.
func Since(r Reading) time.Duration { return time.Duration(now() - r) }
