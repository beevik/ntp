// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//go:build darwin

package ntp

import (
	"encoding/binary"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

type connDarwin struct {
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
		setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TIMESTAMP, 1)
	})
	if err != nil || setErr != nil {
		return newConnFallback(base, opt)
	}

	if err := applyOptions(base, opt); err != nil {
		return nil, err
	}

	conn := &connDarwin{
		base:    base,
		udpConn: udpConn,
		msgBuf:  make([]byte, msgBufSize),
		oobBuf:  make([]byte, oobBufSize),
		getTime: opt.GetSystemTime,
	}
	return conn, nil
}

func (c *connDarwin) Close() error {
	return c.base.Close()
}

func (c *connDarwin) Read() (b []byte, recvTime time.Time, err error) {
	n, oobn, _, _, err := c.udpConn.ReadMsgUDP(c.msgBuf, c.oobBuf)
	if err != nil {
		return nil, c.getTime(), err
	}

	// Get imprecise time in case we can't get a kernel timestamp.
	recvTime = c.getTime()

	// Parse control messages to extract timestamp.
	if oobn > 0 {
		cmsgs, parseErr := unix.ParseSocketControlMessage(c.oobBuf[:oobn])
		if parseErr == nil {
			for _, cmsg := range cmsgs {
				if cmsg.Header.Level == unix.SOL_SOCKET && cmsg.Header.Type == unix.SCM_TIMESTAMP {
					if len(cmsg.Data) >= 12 {
						sec := int64(binary.NativeEndian.Uint64(cmsg.Data[0:8]))
						usec := int64(binary.NativeEndian.Uint32(cmsg.Data[8:12]))
						recvTime = time.Unix(sec, usec*1000).UTC()
						break
					}
				}
			}
		}
	}

	return c.msgBuf[:n], recvTime, nil
}

func (c *connDarwin) Write(b []byte) (n int, err error) {
	return c.base.Write(b)
}
