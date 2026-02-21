// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//go:build !linux && !darwin && !windows

package ntp

import (
	"net"
)

func newConn(base net.Conn, opt *QueryOptions) (conn, error) {
	return newConnFallback(base, opt)
}
