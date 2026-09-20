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
	base          net.Conn
	udpConn       *net.UDPConn
	msgBuf        []byte
	oobBuf        []byte
	getSystemTime func() time.Time
}

func newConn(base net.Conn, opt *QueryOptions, useKernelTime bool) (conn, error) {
	if !useKernelTime {
		return newConnFallback(base, opt)
	}

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
		return nil, err
	}

	conn := &connLinux{
		base:          base,
		udpConn:       udpConn,
		msgBuf:        make([]byte, msgBufSize),
		oobBuf:        make([]byte, oobBufSize),
		getSystemTime: opt.GetSystemTime,
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

	// Get imprecise time in case we can't get a kernel timestamp.
	recvTime = c.getSystemTime()

	// Parse control messages to extract the nanosecond-precision timestamp.
	if oobn > 0 {
		cmsgs, parseErr := unix.ParseSocketControlMessage(c.oobBuf[:oobn])
		if parseErr == nil {
			for _, cmsg := range cmsgs {
				if cmsg.Header.Level != unix.SOL_SOCKET || cmsg.Header.Type != unix.SO_TIMESTAMPNS {
					continue
				}
				if sec, nsec, ok := parseTimeFields(cmsg.Data); ok {
					recvTime = time.Unix(sec, nsec).UTC()
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

func parseTimeFields(data []byte) (sec, nsec int64, ok bool) {
	switch len(data) {
	case 8: // two 32-bit fields
		sec = int64(int32(binary.NativeEndian.Uint32(data[0:4])))
		nsec = int64(int32(binary.NativeEndian.Uint32(data[4:8])))
	case 16: // two 64-bit fields
		sec = int64(binary.NativeEndian.Uint64(data[0:8]))
		nsec = int64(binary.NativeEndian.Uint64(data[8:16]))
	default:
		return 0, 0, false
	}
	return sec, nsec, true
}
