// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//go:build windows

package ntp

import (
	"encoding/binary"
	"net"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type connWindows struct {
	base       net.Conn
	rawConn    syscall.RawConn
	msgBuf     []byte
	ctlBuf     []byte
	wsaMsg     *windows.WSAMsg
	overlapped *windows.Overlapped
	pinner     runtime.Pinner
	getTime    func() time.Time
	timeout    time.Duration
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

	if !enableHardwareTimestamps(rawConn) {
		return newConnFallback(base, opt)
	}

	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return newConnFallback(base, opt)
	}

	if err := applyOptions(base, opt); err != nil {
		return nil, err
	}

	buf := make([]byte, msgBufSize+oobBufSize)
	msgBuf := buf[:msgBufSize]
	ctlBuf := buf[msgBufSize:]

	var pinner runtime.Pinner
	pinner.Pin(&buf[0])

	wsaMsg := &windows.WSAMsg{
		BufferCount: 1,
		Buffers: &windows.WSABuf{
			Len: uint32(len(msgBuf)),
			Buf: &msgBuf[0],
		},
		Control: windows.WSABuf{
			Len: uint32(len(ctlBuf)),
			Buf: &ctlBuf[0],
		},
	}

	overlapped := &windows.Overlapped{
		HEvent: event,
	}

	conn := &connWindows{
		base:       base,
		rawConn:    rawConn,
		msgBuf:     msgBuf,
		ctlBuf:     ctlBuf,
		wsaMsg:     wsaMsg,
		overlapped: overlapped,
		pinner:     pinner,
		getTime:    opt.GetSystemTime,
		timeout:    opt.Timeout,
	}
	return conn, nil
}

func (c *connWindows) Close() error {
	c.pinner.Unpin()
	windows.CloseHandle(c.overlapped.HEvent)
	return c.base.Close()
}

func (c *connWindows) Read() (b []byte, recvTime time.Time, err error) {
	ctl := c.ctlBuf

	var readErr error
	err = c.rawConn.Read(func(fd uintptr) bool {
		// Wait for a response using the WinSock API. Use overlapped I/O to
		// support timeout detection. Results will appear in c.msgBuf and
		// c.ctrlBuf.
		var bytesRead uint32
		readErr = windows.WSARecvMsg(
			windows.Handle(fd),
			c.wsaMsg,
			&bytesRead,
			c.overlapped,
			nil,
		)

		// If the read didn't complete immediately, we need to wait for a
		// response or a timeout, whichever occurs first.
		if readErr == windows.ERROR_IO_PENDING {
			timeoutMs := uint32(c.timeout.Milliseconds())
			waitResult, waitErr := windows.WaitForSingleObject(c.overlapped.HEvent, timeoutMs)
			if waitErr != nil {
				readErr = waitErr
				return true
			}
			if waitResult == ws_WAIT_TIMEOUT {
				windows.CancelIo(windows.Handle(fd))
				readErr = windows.ERROR_TIMEOUT
				return true
			}
			if waitResult != ws_WAIT_OBJECT_0 {
				readErr = windows.ERROR_OPERATION_ABORTED
				return true
			}

			var flags uint32
			readErr = windows.WSAGetOverlappedResult(
				windows.Handle(fd),
				c.overlapped,
				&bytesRead,
				false,
				&flags,
			)
		}

		if readErr != nil {
			return true
		}

		// Get imprecise time in case we can't get a hardware timestamp.
		recvTime = c.getTime()

		b = c.msgBuf[:bytesRead]

		// Truncate the control buffer.
		if c.wsaMsg.Control.Len > 0 && c.wsaMsg.Control.Len <= uint32(len(ctl)) {
			ctl = ctl[:c.wsaMsg.Control.Len]
		} else {
			ctl = ctl[:0]
		}
		return true
	})

	if err != nil {
		return nil, time.Time{}, err
	}
	if readErr != nil {
		return nil, time.Time{}, readErr
	}

	// Parse control messages to extract hardware timestamp (if available).
	if len(ctl) > 0 {
		parsedTime, ok := parseTimestamp(ctl)
		if ok {
			return b, parsedTime, nil
		}
	}

	return b, recvTime, nil
}

func (c *connWindows) Write(b []byte) (n int, err error) {
	return c.base.Write(b)
}

// Winsock API constants.
const (
	ws_SIO_TIMESTAMPING     = 0x980000eb // _WSAIOW(IOC_VENDOR, 235)
	ws_TIMESTAMPING_FLAG_RX = 0x01
	ws_SO_TIMESTAMP         = 0x300a
	ws_WAIT_OBJECT_0        = 0x00000000
	ws_WAIT_TIMEOUT         = 0x00000102
)

// ws_TIMESTAMPING_CONFIG matches the TIMESTAMPING_CONFIG structure from
// mstcpip.h.
type ws_TIMESTAMPING_CONFIG struct {
	Flags                uint64
	TxTimestampsBuffered uint16
	_                    uint16 // padding
}

// ws_WSACMSGHDR matches the WSACMSGHDR structure from mstcpip.h.
type ws_WSACMSGHDR struct {
	Len   uint64
	Level int32
	Type  int32
}

// enableHardwareTimestamps attempts to enable hardware timestamps on Windows
// using SIO_TIMESTAMPING.
func enableHardwareTimestamps(rawConn syscall.RawConn) bool {
	var enabled bool
	_ = rawConn.Control(func(fd uintptr) {
		config := ws_TIMESTAMPING_CONFIG{
			Flags: ws_TIMESTAMPING_FLAG_RX,
		}

		var n uint32
		err := windows.WSAIoctl(
			windows.Handle(fd),
			ws_SIO_TIMESTAMPING,
			(*byte)(unsafe.Pointer(&config)),
			uint32(unsafe.Sizeof(config)),
			nil,
			0,
			&n,
			nil,
			0,
		)
		enabled = err == nil
	})

	return enabled
}

// parseTimestamp extracts the timestamp from a Windows control message.
func parseTimestamp(ctl []byte) (time.Time, bool) {
	hdrsize := int(unsafe.Sizeof(ws_WSACMSGHDR{}))
	for len(ctl) >= hdrsize {
		hdr := (*ws_WSACMSGHDR)(unsafe.Pointer(&ctl[0]))
		if hdr.Len < uint64(hdrsize) {
			break
		}

		if hdr.Level == windows.SOL_SOCKET && hdr.Type == ws_SO_TIMESTAMP {
			offset := hdrsize
			if int(hdr.Len) >= int(offset)+8 {
				// FILETIME is the number of 100-nanosecond intervals since
				// 1601-01-01 (UTC). A value of zero means no hardware
				// timestamp was available.
				filetime := binary.NativeEndian.Uint64(ctl[offset : offset+8])
				if filetime == 0 {
					return time.Time{}, false
				}

				// FILETIME epoch is 1601-01-01, Unix epoch is 1970-01-01.
				const filetimeToUnixOffset = 116_444_736_000_000_000
				if filetime > filetimeToUnixOffset {
					nsec := (filetime - filetimeToUnixOffset) * 100
					return time.Unix(0, int64(nsec)).UTC(), true
				}

				break
			}
		}

		// Move to the next control message.
		offset := (hdr.Len + 3) & ^uint64(3)
		if offset > uint64(len(ctl)) {
			break
		}
		ctl = ctl[offset:]
	}

	return time.Time{}, false
}
