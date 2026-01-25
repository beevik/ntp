// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//go:build !linux && !darwin && !windows

package ntp

import (
	"net"
	"time"
)

// enableHardwareTimestamps is a no-op on unsupported platforms.
func enableHardwareTimestamps(conn net.Conn) error {
	_ = conn
	return nil
}

// readWithTimestamp is a fallback for platforms with no hardware timestamp
// implementation.
func readWithTimestamp(conn net.Conn, b, _ []byte, opt *QueryOptions) (n int, recvTime time.Time, err error) {
	n, err = conn.Read(b)
	return n, opt.GetSystemTime(), err
}
