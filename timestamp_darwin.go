// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//go:build darwin

package ntp

import (
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// enableHardwareTimestamps enables SO_TIMESTAMP on the UDP connection to get
// kernel-level receive timestamps with microsecond precision.
func enableHardwareTimestamps(conn net.Conn) error {
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return nil
	}

	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		return err
	}

	var setErr error
	err = rawConn.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TIMESTAMP, 1)
	})
	if err != nil {
		return err
	}
	return setErr
}

// readWithTimestamp reads from the connection and returns both the data and
// the kernel-level receive timestamp (if available).
func readWithTimestamp(conn net.Conn, b, oob []byte, opt *QueryOptions) (n int, recvTime time.Time, err error) {
	// If we don't have a UDP connection, fallback to imprecise time.
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		n, err = conn.Read(b)
		return n, opt.GetSystemTime(), err
	}

	// Read message with out-of-band control data.
	n, on, _, _, err := udpConn.ReadMsgUDP(b, oob)
	if err != nil {
		return n, opt.GetSystemTime(), err
	}

	// Fallback to imprecise time.
	recvTime = opt.GetSystemTime()

	// Parse control messages to extract timestamp.
	if on > 0 {
		msgs, parseErr := unix.ParseSocketControlMessage(oob[:on])
		if parseErr == nil {
			for _, m := range msgs {
				if m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SCM_TIMESTAMP {
					if len(m.Data) >= 12 {
						sec := int64(nativeEndian.Uint64(m.Data[0:8]))
						usec := int64(nativeEndian.Uint32(m.Data[8:12]))
						recvTime = time.Unix(sec, usec*1000).UTC()
						break
					}
				}
			}
		}
	}

	return n, recvTime, nil
}
