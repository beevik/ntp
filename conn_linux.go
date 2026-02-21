// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//go:build linux

package ntp

import (
	"encoding/binary"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

type connLinux struct {
	base    net.Conn
	udpConn *net.UDPConn
	msgBuf  []byte
	oobBuf  []byte
	getTime func() time.Time
}

func newConn(base net.Conn, opt *QueryOptions) (conn, error) {
	udpConn, ok := base.(*net.UDPConn)
	if !ok {
		return newConnFallback(base, opt)
	}

	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		return newConnFallback(base, opt)
	}

	var setErr error
	err = rawConn.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1)
	})
	if err != nil || setErr != nil {
		return newConnFallback(base, opt)
	}

	if err := applyOptions(base, opt); err != nil {
		return newConnFallback(base, opt)
	}

	conn := &connLinux{
		base:    base,
		udpConn: udpConn,
		msgBuf:  make([]byte, msgBufSize),
		oobBuf:  make([]byte, oobBufSize),
		getTime: opt.GetSystemTime,
	}
	return conn, nil
}

func (c *connLinux) Close() error {
	return c.base.Close()
}

func (c *connLinux) Read() (b []byte, recvTime time.Time, err error) {
	n, oobn, _, _, err := c.udpConn.ReadMsgUDP(c.msgBuf, c.oobBuf)
	if err != nil {
		return nil, time.Time{}, err
	}

	// Get imprecise time in case we can't get a hardware timestamp.
	recvTime = c.getTime()

	// Parse control messages to extract timestamp.
	if oobn > 0 {
		cmsgs, parseErr := unix.ParseSocketControlMessage(c.oobBuf[:oobn])
		if parseErr == nil {
			for _, cmsg := range cmsgs {
				// Try nanosecond precision first.
				if cmsg.Header.Level == unix.SOL_SOCKET && cmsg.Header.Type == unix.SO_TIMESTAMPNS {
					sec := int64(binary.NativeEndian.Uint64(cmsg.Data[0:8]))
					nsec := int64(binary.NativeEndian.Uint64(cmsg.Data[8:16]))
					recvTime = time.Unix(sec, nsec).UTC()
					break
				}

				// Fallback to microsecond precision.
				if cmsg.Header.Level == unix.SOL_SOCKET && cmsg.Header.Type == unix.SO_TIMESTAMP {
					sec := int64(binary.NativeEndian.Uint64(cmsg.Data[0:8]))
					usec := int64(binary.NativeEndian.Uint64(cmsg.Data[8:16]))
					recvTime = time.Unix(sec, usec*1000).UTC()
					break
				}
			}
		}
	}

	return c.msgBuf[:n], recvTime, nil
}

func (c *connLinux) Write(b []byte) (n int, err error) {
	return c.base.Write(b)
}
