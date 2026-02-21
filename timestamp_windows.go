// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//go:build windows

package ntp

import (
	"encoding/binary"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows API constants.
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

// enableHardwareTimestamps enables hardware timestamping on Windows using
// SIO_TIMESTAMPING. If timestamping is not supported, it silently ignores
// the error and falls back to application-level timestamps.
func enableHardwareTimestamps(conn net.Conn) error {
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return nil
	}

	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		return nil
	}

	_ = rawConn.Control(func(fd uintptr) {
		config := ws_TIMESTAMPING_CONFIG{
			Flags: ws_TIMESTAMPING_FLAG_RX,
		}

		var n uint32
		err = windows.WSAIoctl(
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
		_ = err
	})

	return nil
}

// readWithTimestamp reads from the connection and returns both the data and
// the kernel-level receive timestamp (if available).
func readWithTimestamp(conn net.Conn, b, cb []byte, opt *QueryOptions) (n int, recvTime time.Time, err error) {
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		n, err = conn.Read(b)
		return n, opt.GetSystemTime(), err
	}

	// Get the raw file descriptor.
	rawConn, err := udpConn.SyscallConn()
	if err != nil {
		n, err = conn.Read(b)
		return n, opt.GetSystemTime(), err
	}

	// Use WSARecvMsg to receive the message with control data.
	var readErr error
	err = rawConn.Read(func(fd uintptr) bool {

		// Create an event for overlapped I/O so we can implement a timeout.
		event, evtErr := windows.CreateEvent(nil, 0, 0, nil)
		if evtErr != nil {
			readErr = evtErr
			return true
		}
		defer windows.CloseHandle(event)

		dataBuf := windows.WSABuf{
			Len: uint32(len(b)),
			Buf: &b[0],
		}
		controlBuf := windows.WSABuf{
			Len: uint32(len(cb)),
			Buf: &cb[0],
		}
		msg := windows.WSAMsg{
			Buffers:     &dataBuf,
			BufferCount: 1,
			Control:     controlBuf,
		}
		overlapped := &windows.Overlapped{
			HEvent: event,
		}

		var bytesRead uint32
		readErr = windows.WSARecvMsg(
			windows.Handle(fd),
			&msg,
			&bytesRead,
			overlapped,
			nil,
		)

		// If the read didn't complete immediately, we might need to wait.
		if readErr != nil {
			if readErr != windows.ERROR_IO_PENDING {
				return true
			}

			// Wait until the timeout for a response.
			timeoutMs := uint32(opt.Timeout.Milliseconds())
			waitResult, waitErr := windows.WaitForSingleObject(event, timeoutMs)
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
				overlapped,
				&bytesRead,
				false,
				&flags,
			)
			if readErr != nil {
				return true
			}
		}

		// Capture fallback receive time as soon as possible after the message
		// has been read.
		recvTime = opt.GetSystemTime()
		n = int(bytesRead)

		// Truncate the control buffer.
		if msg.Control.Len > 0 && msg.Control.Len <= uint32(len(cb)) {
			cb = cb[:msg.Control.Len]
		} else {
			cb = nil
		}
		return true
	})

	if err != nil {
		return 0, time.Time{}, err
	}
	if readErr != nil {
		return 0, time.Time{}, readErr
	}

	// Parse control messages to extract kernel timestamp (if available)
	if len(cb) > 0 {
		parsedTime, ok := parseTimestamp(cb)
		if ok {
			return n, parsedTime, nil
		}
	}

	return n, recvTime, nil
}

// parseTimestamp extracts the timestamp from a Windows control message.
func parseTimestamp(controlBuf []byte) (time.Time, bool) {
	hdrsize := int(unsafe.Sizeof(ws_WSACMSGHDR{}))
	for len(controlBuf) >= hdrsize {
		hdr := (*ws_WSACMSGHDR)(unsafe.Pointer(&controlBuf[0]))
		if hdr.Len < uint64(hdrsize) {
			break
		}

		if hdr.Level == windows.SOL_SOCKET && hdr.Type == ws_SO_TIMESTAMP {
			offset := hdrsize
			if int(hdr.Len) >= int(offset)+8 {
				data := controlBuf[offset : offset+8]

				// FILETIME is the number of 100-nanosecond intervals since
				// 1601-01-01 (UTC). A value of zero means no hardware
				// timestamp was available.
				filetime := binary.NativeEndian.Uint64(data[0:8])
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
		if offset > uint64(len(controlBuf)) {
			break
		}
		controlBuf = controlBuf[offset:]
	}

	return time.Time{}, false
}
