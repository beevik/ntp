// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ntp

import (
	"net"
	"time"

	"golang.org/x/net/ipv4"
)

const (
	msgBufSize = 8192
	oobBufSize = 128
)

// conn is a wrapper for an underlying net.Conn type. It provides
// platform-specific support for reading hardware timestamps when available.
type conn interface {
	// Close the connection.
	Close() error

	// Read a message from the connection. It returns the received message,
	// the hardware receive timestamp (if available), and any error
	// encountered. If hardware timestamps are unavailable, it returns the
	// less precise software-based system timestamp instead.
	Read() (b []byte, recvTime time.Time, err error)

	// Write a message to the connection.
	Write(b []byte) (n int, err error)
}

func applyOptions(c net.Conn, opt *QueryOptions) error {
	if opt.TTL != 0 {
		ipconn := ipv4.NewConn(c)
		if err := ipconn.SetTTL(opt.TTL); err != nil {
			return err
		}
	}

	err := c.SetDeadline(time.Now().Add(opt.Timeout))
	return err
}

// connFallback is a fallback implementation of the conn interface, used
// when only software-based timestamps are available.
type connFallback struct {
	base    net.Conn
	msgBuf  []byte
	getTime func() time.Time
}

func newConnFallback(base net.Conn, opt *QueryOptions) (conn, error) {
	if err := applyOptions(base, opt); err != nil {
		return nil, err
	}

	conn := &connFallback{
		base:    base,
		msgBuf:  make([]byte, msgBufSize),
		getTime: opt.GetSystemTime,
	}
	return conn, nil
}

func (c *connFallback) Close() error {
	return c.base.Close()
}

func (c *connFallback) Read() (b []byte, recvTime time.Time, err error) {
	n, err := c.base.Read(c.msgBuf)
	if err != nil {
		return nil, time.Time{}, err
	}
	return c.msgBuf[:n], c.getTime(), nil
}

func (c *connFallback) Write(b []byte) (n int, err error) {
	return c.base.Write(b)
}
