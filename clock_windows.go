// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//go:build windows

package ntp

import (
	"time"

	"golang.org/x/sys/windows"
)

// getSystemTime returns the current system time in UTC.
func getSystemTime() time.Time {
	// On Windows, time.Now reads a shared system time value that the kernel
	// updates once per timer tick, so its resolution is on the order of
	// hundreds of microseconds. GetSystemTimePreciseAsFileTime interpolates
	// between ticks using the performance counter, yielding 100-nanosecond
	// resolution.
	var ft windows.Filetime
	windows.GetSystemTimePreciseAsFileTime(&ft)
	return time.Unix(0, ft.Nanoseconds()).UTC()
}
