//go:build !windows

package clock

import "time"

var origin = time.Now()

func now() Reading { return Reading(time.Since(origin)) }
