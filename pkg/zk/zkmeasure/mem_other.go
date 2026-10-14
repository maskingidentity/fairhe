//go:build !windows

package zkmeasure

// PeakMemory is unavailable outside Windows in this prototype; the
// measurement records the columns as absent.
func PeakMemory() (rss, commit uint64, ok bool) { return 0, 0, false }
