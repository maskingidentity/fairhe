//go:build windows

package zkmeasure

import (
	"syscall"
	"unsafe"
)

// processMemoryCounters mirrors the Win32 PROCESS_MEMORY_COUNTERS struct
// (psapi.h).
type processMemoryCounters struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uintptr
	workingSetSize             uintptr
	quotaPeakPagedPoolUsage    uintptr
	quotaPagedPoolUsage        uintptr
	quotaPeakNonPagedPoolUsage uintptr
	quotaNonPagedPoolUsage     uintptr
	pagefileUsage              uintptr
	peakPagefileUsage          uintptr
}

var procGetProcessMemoryInfo = syscall.NewLazyDLL("psapi.dll").NewProc("GetProcessMemoryInfo")

// PeakMemory returns the process's peak working set and peak commit
// (private bytes), the quantity bounded by the machine's commit limit.
func PeakMemory() (rss, commit uint64, ok bool) {
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, 0, false
	}
	var pmc processMemoryCounters
	pmc.cb = uint32(unsafe.Sizeof(pmc))
	r1, _, _ := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&pmc)), uintptr(unsafe.Sizeof(pmc)))
	if r1 == 0 {
		return 0, 0, false
	}
	return uint64(pmc.peakWorkingSetSize), uint64(pmc.peakPagefileUsage), true
}
