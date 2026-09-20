//go:build !linux && !darwin

// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ntp

import (
	"net"
)

func newConn(base net.Conn, opt *QueryOptions, _ bool) (conn, error) {
	return newConnFallback(base, opt)
}
