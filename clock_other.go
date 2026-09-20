// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//go:build !windows

package ntp

import "time"

// getSystemTime returns the current system time in UTC.
func getSystemTime() time.Time {
	return time.Now().UTC()
}
