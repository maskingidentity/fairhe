package clock

import (
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	qpc      = kernel32.NewProc("QueryPerformanceCounter")
	freq     = func() int64 {
		var f int64
		kernel32.NewProc("QueryPerformanceFrequency").Call(uintptr(unsafe.Pointer(&f)))
		return f
	}()
)

// now returns the performance counter in nanoseconds.
func now() Reading {
	var c int64
	qpc.Call(uintptr(unsafe.Pointer(&c)))
	return Reading(c/freq*1e9 + c%freq*1e9/freq)
}
