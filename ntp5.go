// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// EXPERIMENTAL: NTPv5 support is based on draft-ietf-ntp-ntpv5 and is subject
// to change as the specification evolves. Do not use in production
// environments.

package ntp

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"net"
	"time"
)

// Timescale represents the time reference system used by an NTPv5 server.
type Timescale uint8

const (
	// TimescaleUTC indicates Coordinated Universal Time with leap seconds.
	TimescaleUTC Timescale = 0

	// TimescaleTAI indicates International Atomic Time.
	TimescaleTAI Timescale = 1

	// TimescaleUT1 indicates Universal Time based on Earth's rotation.
	TimescaleUT1 Timescale = 2

	// TimescaleLeapSmeared indicates UTC with leap seconds smeared.
	TimescaleLeapSmeared Timescale = 3
)

// NTPv5 mode.
type modeV5 uint8

const (
	requestMode  modeV5 = 3
	responseMode modeV5 = 4
)

type extType uint16

const (
	extPadding            extType = 0xf501
	extMAC                extType = 0xf502
	extRefIDReq           extType = 0xf503
	extRefIDResp          extType = 0xf504
	extServerInfo         extType = 0xf505
	extCorrection         extType = 0xf506
	extRefTimestamp       extType = 0xf507
	extMonotonicTimestamp extType = 0xf508
	extSecondaryTimestamp extType = 0xf509
	extDraftID            extType = 0xf5ff
)

const (
	// The currently supported draft version.
	draftID = "draft-ietf-ntp-ntpv5-07"
)

// timeShortV5 is a 32-bit fixed-point (Q4.28) representation of the number
// of seconds elapsed with 4ns precision.
type timeShortV5 uint32

// Duration converts a timeShortV5 value to a Duration value.
func (t timeShortV5) Duration() time.Duration {
	t0 := uint64(t>>28) * nanoPerSec
	f1 := uint64(t&mask28) * nanoPerSec
	t1 := f1 >> 28
	t1 += uint64((f1&mask28)+half28) >> 28 // round half up
	return time.Duration(t0 + t1)
}

// toTimeShortV5 converts a Duration to a fixed-point timeShortV5
// representation.
func toTimeShortV5(d time.Duration) timeShortV5 {
	if d <= 0 {
		return 0
	}

	nsec := uint64(d)
	sec := nsec / nanoPerSec
	if sec > 15 {
		return 0xffff_ffff
	}

	remainder := nsec - sec*nanoPerSec
	remainderShifted := remainder << 28
	frac := (remainderShifted + nanoPerSec/2) / nanoPerSec
	return timeShortV5((sec << 28) | frac)
}

// timeCorrectionV5 is a 64-bit fixed-point (Q48.16) representation of the
// number of seconds elapsed with 15.3us precision.
type timeCorrectionV5 uint64

// Duration converts a timeCorrectionV5 value to a Duration value.
func (t timeCorrectionV5) Duration() time.Duration {
	t0 := uint64(t>>16) * nanoPerSec
	f1 := uint64(t&mask16) * nanoPerSec
	t1 := f1 >> 16
	t1 += uint64((f1&mask16)+half16) >> 16 // round half up
	return time.Duration(t0 + t1)
}

// messageV5 is an internal representation of an NTPv5 message.
type messageV5 struct {
	LiVnMode     uint8 // Leap Indicator (2) + Version (3) + Mode (3)
	Stratum      uint8
	Poll         int8
	Precision    int8
	RootDelay    timeShortV5
	RootDisp     timeShortV5
	Timescale    uint8
	Era          uint8
	Flags        uint16
	ServerCookie uint64
	ClientCookie uint64
	ReceiveTime  timestamp
	TransmitTime timestamp
}

// NTPv5 message flag values.
const (
	flagSynchronized = 1 << 0
	flagInterleaved  = 1 << 1
	flagAuthNAK      = 1 << 2
)

// setVersion sets the NTP protocol version on the message.
func (m *messageV5) setVersion(v int) {
	m.LiVnMode = (m.LiVnMode & 0xc7) | uint8(v)<<3
}

// setMode sets the NTP protocol mode on the message.
func (m *messageV5) setMode(md modeV5) {
	m.LiVnMode = (m.LiVnMode & 0xf8) | uint8(md)
}

// setLeap modifies the leap indicator on the message.
func (m *messageV5) setLeap(li LeapIndicator) {
	m.LiVnMode = (m.LiVnMode & 0x3f) | uint8(li)<<6
}

// getVersion returns the version value in the message.
func (m *messageV5) getVersion() int {
	return int((m.LiVnMode >> 3) & 0x7)
}

// getMode returns the mode value in the message.
func (m *messageV5) getMode() modeV5 {
	return modeV5(m.LiVnMode & 0x07)
}

// getLeap returns the leap indicator on the message.
func (m *messageV5) getLeap() LeapIndicator {
	return LeapIndicator((m.LiVnMode >> 6) & 0x03)
}

// parseV5Response parses the NTPv5 response message from a buffer.
func parseV5Response(data []byte) (*messageV5, error) {
	if len(data) < msgSize {
		return nil, ErrInvalidTime
	}

	m := &messageV5{}
	r := bytes.NewReader(data)

	binary.Read(r, binary.BigEndian, &m.LiVnMode)
	binary.Read(r, binary.BigEndian, &m.Stratum)
	binary.Read(r, binary.BigEndian, &m.Poll)
	binary.Read(r, binary.BigEndian, &m.Precision)
	binary.Read(r, binary.BigEndian, &m.RootDelay)
	binary.Read(r, binary.BigEndian, &m.RootDisp)
	binary.Read(r, binary.BigEndian, &m.Timescale)
	binary.Read(r, binary.BigEndian, &m.Era)
	binary.Read(r, binary.BigEndian, &m.Flags)
	binary.Read(r, binary.BigEndian, &m.ServerCookie)
	binary.Read(r, binary.BigEndian, &m.ClientCookie)
	binary.Read(r, binary.BigEndian, &m.ReceiveTime)
	binary.Read(r, binary.BigEndian, &m.TransmitTime)

	return m, nil
}

// queryV5 performs an NTPv5 time query using the provided connection.
func queryV5(conn net.Conn, opt *QueryOptions) (*Response, error) {
	// Generate a random client cookie if not set by the caller.
	clientCookie, err := generateCookie()
	if err != nil {
		return nil, err
	}

	// Decode the authentication key if symmetric key authentication has been
	// requested.
	authKey, err := decodeAuthKey(opt.Auth)
	if err != nil {
		return nil, err
	}

	// Allocate a buffer big enough to hold an entire response datagram.
	recvBuf := make([]byte, 8192)

	// Build the NTPv5 request along with most extension fields into a buffer.
	xmitBuf, err := buildV5Request(opt, clientCookie)
	if err != nil {
		return nil, err
	}

	// Update the transmit timestamp at the last possible moment.
	clientXmitTime := opt.GetSystemTime()
	binary.BigEndian.PutUint64(xmitBuf.Bytes()[40:], uint64(toTimestamp(clientXmitTime)))

	// The MAC extension field must be appended after the transmit timestamp
	// has been written.
	if authKey != nil {
		mac := calcMAC(xmitBuf.Bytes(), opt.Auth.Type, authKey)
		writeExtMAC(xmitBuf, opt.Auth.KeyID, mac)
	}

	// The correction extension field must be last. It is not covered by the
	// MAC.
	if opt.RequestCorrection {
		writeExtCorrection(xmitBuf)
	}

	// Send the request message.
	_, err = conn.Write(xmitBuf.Bytes())
	if err != nil {
		return nil, err
	}

	// Receive the response message.
	n, err := conn.Read(recvBuf)
	if err != nil {
		return nil, err
	}

	// Keep track of the time the response message was received.
	clientRecvTime := opt.GetSystemTime()

	// Parse the response message.
	recvBuf = recvBuf[:n]
	m, err := parseV5Response(recvBuf)
	if err != nil {
		return nil, err
	}

	// Check for invalid fields in the response message.
	if m.getMode() != responseMode {
		return nil, ErrInvalidMode
	}
	if m.getVersion() != 5 {
		return nil, ErrInvalidProtocolVersion
	}
	if m.ClientCookie != clientCookie {
		return nil, ErrServerResponseMismatch
	}

	// Prepare the response struct.
	r := &Response{
		Version: 5,
	}

	// Check for an authentication NAK.
	if m.Flags&flagAuthNAK != 0 {
		r.authErr = ErrAuthNAK
	}

	// Convert timestamps.
	serverRecvTime := timestamp(m.ReceiveTime).Time(m.Era)
	serverXmitTime := timestamp(m.TransmitTime).Time(m.Era)

	// Start filling in response fields.
	r.Time = serverXmitTime
	r.Precision = toInterval(m.Precision)
	r.Stratum = m.Stratum
	r.Leap = m.getLeap()
	r.Poll = toInterval(m.Poll)
	r.Timescale = Timescale(m.Timescale)
	r.Era = m.Era
	r.ServerCookie = m.ServerCookie

	// Determine response flags.
	if m.Flags&flagSynchronized != 0 {
		r.Flags |= FlagSynchronized
	}
	if m.Flags&flagInterleaved != 0 {
		r.Flags |= FlagInterleaved
	}

	// Calculate the clock offset and round trip time.
	// offset = ((t2 - t1) + (t3 - t4)) / 2
	// rtt = (t4 - t1) - (t3 - t2)
	t1 := clientXmitTime
	t2 := serverRecvTime
	t3 := serverXmitTime
	t4 := clientRecvTime
	r.ClockOffset = (t2.Sub(t1) + t3.Sub(t4)) / 2
	r.RTT = max(t4.Sub(t1)-t3.Sub(t2), 0)

	// Calculate root dispersion and distance.
	r.RootDelay = m.RootDelay.Duration()
	r.RootDispersion = m.RootDisp.Duration()
	r.RootDistance = (r.RTT+r.RootDelay)/2 + r.RootDispersion

	// Calculate min error (causality violation detection).
	if t2.Before(t1) || t4.Before(t3) {
		r.MinError = max(t1.Sub(t2), t3.Sub(t4))
	}

	// Process extension fields.
	offset := msgSize
	curr := recvBuf[offset:]
	for len(curr) >= 4 {
		xtype := extType(binary.BigEndian.Uint16(curr[0:2]))
		xlen := int(binary.BigEndian.Uint16(curr[2:4]))
		if len(curr) < xlen {
			return nil, ErrInvalidExtensionField
		}

		body := curr[4:xlen]

		switch xtype {
		case extPadding:
			// Ignore padding.

		case extMAC:
			if len(body[4:]) != getMACSize(opt.Auth.Type) {
				return nil, ErrAuthFailed
			}
			mac := calcMAC(recvBuf[:offset], opt.Auth.Type, authKey)
			if subtle.ConstantTimeCompare(mac, body[4:]) == 0 {
				r.authErr = ErrAuthFailed
			}

		case extRefIDResp:
			r.ReferenceIDFilterValues = body

		case extServerInfo:
			bits := binary.BigEndian.Uint16(body[0:2])
			for v := 3; v <= 5; v++ {
				if bits&(1<<uint16(v-1)) != 0 {
					r.SupportedVersions = append(r.SupportedVersions, v)
				}
			}

		case extCorrection:
			if len(body) != 24 {
				return nil, ErrInvalidExtensionField
			}
			r.Correction.Origin = timeCorrectionV5(binary.BigEndian.Uint64(body[0:8])).Duration()
			r.Correction.OriginPathID = binary.BigEndian.Uint16(body[8:10])
			r.Correction.Delay = timeCorrectionV5(binary.BigEndian.Uint64(body[12:20])).Duration()
			r.Correction.DelayPathID = binary.BigEndian.Uint16(body[20:22])

		case extRefTimestamp:
			if len(body) != 8 {
				return nil, ErrInvalidExtensionField
			}
			r.ReferenceTime = timestamp(binary.BigEndian.Uint64(body)).Time(m.Era)

		case extMonotonicTimestamp:
			if len(body) != 12 {
				return nil, ErrInvalidExtensionField
			}
			r.MonotonicEpochID = binary.BigEndian.Uint32(body[0:4])
			r.MonotonicTime = timestamp(binary.BigEndian.Uint64(body[4:12])).Time(m.Era)

		case extSecondaryTimestamp:
			if len(body) != 12 {
				return nil, ErrInvalidExtensionField
			}
			era := uint8(body[1])
			r.SecondaryTime = timestamp(binary.BigEndian.Uint64(body[4:12])).Time(era)

		case extDraftID:
			if string(body[:len(draftID)]) != draftID {
				return nil, ErrInvalidDraftID
			}
		}

		offset += paddedLen(xlen)
		curr = recvBuf[offset:]
	}

	// Allow package extensions to process the response.
	for i := len(opt.Extensions) - 1; i >= 0; i-- {
		err = opt.Extensions[i].ProcessResponse(recvBuf)
		if err != nil {
			return nil, err
		}
	}

	return r, r.authErr
}

// buildV5Request creates an NTPv5 request message and adds all extension
// fields except for the MAC and correction extension fields.
func buildV5Request(opt *QueryOptions, clientCookie uint64) (*bytes.Buffer, error) {
	// Build the NTPv5 message.
	m := messageV5{
		Precision:    0,
		Stratum:      0,
		Poll:         0,
		RootDelay:    0,
		RootDisp:     0,
		Timescale:    uint8(opt.Timescale),
		Era:          0,
		Flags:        0,
		ServerCookie: opt.ServerCookie,
		ClientCookie: clientCookie,
		ReceiveTime:  0,
		TransmitTime: 0,
	}
	m.setVersion(5)
	m.setMode(requestMode)
	m.setLeap(LeapNoWarning)

	if opt.RequestInterleavedMode {
		m.Flags |= flagInterleaved
	}

	// Write the message to a buffer.
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, m.LiVnMode)
	binary.Write(buf, binary.BigEndian, m.Stratum)
	binary.Write(buf, binary.BigEndian, m.Poll)
	binary.Write(buf, binary.BigEndian, m.Precision)
	binary.Write(buf, binary.BigEndian, m.RootDelay)
	binary.Write(buf, binary.BigEndian, m.RootDisp)
	binary.Write(buf, binary.BigEndian, m.Timescale)
	binary.Write(buf, binary.BigEndian, m.Era)
	binary.Write(buf, binary.BigEndian, m.Flags)
	binary.Write(buf, binary.BigEndian, m.ServerCookie)
	binary.Write(buf, binary.BigEndian, m.ClientCookie)
	binary.Write(buf, binary.BigEndian, m.ReceiveTime)
	binary.Write(buf, binary.BigEndian, m.TransmitTime)

	// The draft identification extension field will be removed once NTPv5 is
	// finalized.
	writeExtDraftID(buf)

	if opt.ReferenceIDRequest.ChunkSize > 0 {
		request := opt.ReferenceIDRequest
		if request.ChunkOffset+request.ChunkSize > 512 ||
			request.ChunkOffset%4 != 0 ||
			request.ChunkSize%4 != 0 {
			return nil, ErrInvalidReferenceRequest
		}
		writeExtRefIDRequest(buf, opt.ReferenceIDRequest)
	}

	if opt.RequestSupportedVersions {
		writeExtServerInfo(buf)
	}

	if opt.RequestReferenceTime {
		writeRefTimestamp(buf)
	}

	if opt.RequestMonotonicTime {
		writeExtMonotonicTimestamp(buf)
	}

	if opt.SecondaryTimescale != opt.Timescale {
		writeExtSecondaryTimestamp(buf, opt.SecondaryTimescale)
	}

	// Allow package extensions to process modify the transmit buffer.
	for _, e := range opt.Extensions {
		err := e.ProcessQuery(buf)
		if err != nil {
			return nil, err
		}
	}

	return buf, nil
}

// generateCookie creates a random non-zero 64-bit cookie value.
func generateCookie() (uint64, error) {
	for {
		var cookieBytes [8]byte
		_, err := rand.Read(cookieBytes[:])
		if err != nil {
			return 0, err
		}

		cookie := binary.BigEndian.Uint64(cookieBytes[:])
		if cookie != 0 {
			return cookie, nil
		}
	}
}

func writeExtDraftID(buf *bytes.Buffer) {
	valueLenPadded := paddedLen(len(draftID))
	totalLen := 4 + len(draftID) // Confirm that length shouldn't include pad!

	binary.Write(buf, binary.BigEndian, extDraftID)
	binary.Write(buf, binary.BigEndian, uint16(totalLen))
	buf.Write([]byte(draftID))
	buf.Write(padBytes[:valueLenPadded-len(draftID)])
}

func writeExtRefIDRequest(buf *bytes.Buffer, req ReferenceIDRequest) {
	binary.Write(buf, binary.BigEndian, extRefIDReq)
	binary.Write(buf, binary.BigEndian, req.ChunkSize+4)
	binary.Write(buf, binary.BigEndian, req.ChunkOffset)
	buf.Write(make([]byte, req.ChunkSize-2))
}

func writeExtServerInfo(buf *bytes.Buffer) {
	binary.Write(buf, binary.BigEndian, extServerInfo)
	binary.Write(buf, binary.BigEndian, uint16(8))
	binary.Write(buf, binary.BigEndian, uint32(0))
}

func writeExtMAC(buf *bytes.Buffer, keyID uint32, mac []byte) {
	binary.Write(buf, binary.BigEndian, extMAC)
	binary.Write(buf, binary.BigEndian, uint16(8+len(mac)))
	binary.Write(buf, binary.BigEndian, keyID)
	buf.Write(mac)
}

func writeExtCorrection(buf *bytes.Buffer) {
	binary.Write(buf, binary.BigEndian, extCorrection)
	binary.Write(buf, binary.BigEndian, uint16(28))
	buf.Write(make([]byte, 24))
}

func writeRefTimestamp(buf *bytes.Buffer) {
	binary.Write(buf, binary.BigEndian, extRefTimestamp)
	binary.Write(buf, binary.BigEndian, uint16(12))
	binary.Write(buf, binary.BigEndian, uint64(0))
}

func writeExtMonotonicTimestamp(buf *bytes.Buffer) {
	binary.Write(buf, binary.BigEndian, extMonotonicTimestamp)
	binary.Write(buf, binary.BigEndian, uint16(16))
	binary.Write(buf, binary.BigEndian, uint32(0))
	binary.Write(buf, binary.BigEndian, uint64(0))
}

func writeExtSecondaryTimestamp(buf *bytes.Buffer, timescale Timescale) {
	binary.Write(buf, binary.BigEndian, extSecondaryTimestamp)
	binary.Write(buf, binary.BigEndian, uint16(16))
	binary.Write(buf, binary.BigEndian, uint8(timescale))
	buf.Write(make([]byte, 11))
}

var padBytes = make([]byte, 4)

func paddedLen(len int) int {
	return (len + 3) & ^3
}
