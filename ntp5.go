// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// EXPERIMENTAL: This file implements NTP versions 3 and 4 (NTPv3 and NTPv4)
// protocol support. It is based on draft-ietf-ntp-ntpv5 and is subject to
// change as the specification evolves. Do not use in production environments.

package ntp

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"time"
)

var (
	ErrInvalidDraftID            = errors.New("invalid draft ID value in response")
	ErrInvalidExtensionField     = errors.New("invalid extension field in response")
	ErrInvalidReferenceRequest   = errors.New("invalid reference ID request")
	ErrUnexpectedCorrectionField = errors.New("unexpected correction extension field in response")
)

// Timescale represents the time reference system used by an NTPv5 server.
type Timescale uint8

const (
	// TimescaleUTC indicates Coordinated Universal Time (UTC) with leap
	// seconds.
	TimescaleUTC Timescale = 0

	// TimescaleTAI indicates International Atomic Time.
	TimescaleTAI Timescale = 1

	// TimescaleUT1 indicates Universal Time based on Earth's rotation.
	TimescaleUT1 Timescale = 2

	// TimescaleUTCSmeared indicates UTC with time-smeared leap seconds.
	TimescaleUTCSmeared Timescale = 3
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

	// Maximum assumed frequency error for devices measuring delay corrections
	// (100ppm)
	maxFrequencyError = 1e-4
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
	// Handle the "unrepresentable" value by returning a sentinel value.
	if t == math.MaxUint64 {
		return DelayUnrepresentable
	}

	// Handle negative values.
	if t&(1<<63) != 0 {
		return -timeCorrectionV5(^t + 1).Duration()
	}

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

// queryV5 performs an NTPv5 time query using the provided connection.
func queryV5(conn net.Conn, opt *QueryOptions) (*Response, error) {
	// Generate a random client cookie if not set by the caller.
	clientCookie, err := randUint64()
	if err != nil {
		return nil, err
	}

	// Decode the authentication key if symmetric key authentication has been
	// requested.
	var authKey []byte
	if opt.Auth.Type != AuthNone {
		authKey, err = decodeAuthKey(opt.Auth)
		if err != nil {
			return nil, err
		}
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
		mac := calcMAC(opt.Version, opt.Auth.Type, authKey, xmitBuf.Bytes())
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
	recvBuf = recvBuf[:n]

	// Keep track of the time the response message was received.
	clientRecvTime := opt.GetSystemTime()

	// Allow package extensions to process the response buffer.
	for i := len(opt.Extensions) - 1; i >= 0; i-- {
		err = opt.Extensions[i].ProcessResponse(recvBuf)
		if err != nil {
			return nil, err
		}
	}

	// Parse the response message.
	m, err := parseV5Response(recvBuf)
	if err != nil {
		return nil, err
	}

	// Compare cookies.
	if m.ClientCookie != clientCookie {
		return nil, ErrServerResponseMismatch
	}

	// Convert timestamps to times.
	serverRecvTime := timestamp(m.ReceiveTime).Time(m.Era)
	serverXmitTime := timestamp(m.TransmitTime).Time(m.Era)

	// Timestamp aliases for readability.
	t1 := clientXmitTime
	t2 := serverRecvTime
	t3 := serverXmitTime
	t4 := clientRecvTime

	// Prepare the response struct.
	r := &Response{
		ClockOffset:    offset(t1, t2, t3, t4),
		RTT:            rtt(t1, t2, t3, t4),
		Timestamps:     ProtocolTimestamps{t1, t2, t3, t4},
		Precision:      toInterval(m.Precision),
		Version:        5,
		Stratum:        m.Stratum,
		Timescale:      Timescale(m.Timescale),
		Era:            m.Era,
		RootDelay:      m.RootDelay.Duration(),
		RootDispersion: m.RootDisp.Duration(),
		Leap:           m.getLeap(),
		MinError:       minError(t1, t2, t3, t4),
		Poll:           toInterval(m.Poll),
		Flags:          0,
		ServerCookie:   m.ServerCookie,
		Time:           serverXmitTime,
	}

	// Calculate root distance.
	r.RootDistance = rootDistance(r.RTT, r.RootDelay, r.RootDispersion)

	// Determine response flags.
	if m.Flags&flagSynchronized != 0 {
		r.Flags |= FlagSynchronized
	}
	if m.Flags&flagInterleaved != 0 {
		r.Flags |= FlagInterleaved
	}

	// Check for an authentication NAK.
	if m.Flags&flagAuthNAK != 0 {
		r.authErr = ErrAuthNAK
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
			if len(body[4:]) != getMACSize(opt.Version, opt.Auth.Type) {
				return nil, ErrAuthFailed
			}
			mac := calcMAC(opt.Version, opt.Auth.Type, authKey, recvBuf[:offset])
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
			if !opt.RequestCorrection {
				return nil, ErrUnexpectedCorrectionField
			}
			if len(body) != 24 {
				return nil, ErrInvalidExtensionField
			}
			r.Correction.OriginDelay = timeCorrectionV5(binary.BigEndian.Uint64(body[0:8])).Duration()
			r.Correction.OriginPathID = binary.BigEndian.Uint16(body[8:10])
			r.Correction.ReturnDelay = timeCorrectionV5(binary.BigEndian.Uint64(body[12:20])).Duration()
			r.Correction.ReturnPathID = binary.BigEndian.Uint16(body[20:22])
			c0 := r.Correction.OriginDelay
			c1 := r.Correction.ReturnDelay
			if c0 >= 0 && c1 >= 0 {
				rtt := r.RTT - time.Duration(float64(c0+c1)*(1.0-maxFrequencyError))
				if rtt >= 0 {
					r.RTT = rtt
					r.ClockOffset += (c1 - c0) / 2
				}
			}

		case extRefTimestamp:
			if len(body) != 8 {
				return nil, ErrInvalidExtensionField
			}
			r.ReferenceTime = timestamp(binary.BigEndian.Uint64(body)).Time(m.Era)

		case extMonotonicTimestamp:
			if len(body) != 12 {
				return nil, ErrInvalidExtensionField
			}
			monotonicRecvTime := timestamp(binary.BigEndian.Uint64(body[4:12])).Time(m.Era)
			r.MonotonicOffset = monotonicRecvTime.Sub(serverRecvTime)
			r.MonotonicEpochID = binary.BigEndian.Uint32(body[0:4])

		case extSecondaryTimestamp:
			if len(body) != 12 {
				return nil, ErrInvalidExtensionField
			}
			era2 := uint8(body[1])
			time2 := timestamp(binary.BigEndian.Uint64(body[4:12])).Time(era2)
			r.TimescaleOffsets = append(r.TimescaleOffsets, TimescaleOffset{
				Timescale: Timescale(body[0]),
				Offset:    time2.Sub(serverRecvTime),
			})

		case extDraftID:
			if string(body[:len(draftID)]) != draftID {
				return nil, ErrInvalidDraftID
			}
		}

		offset += paddedLen(xlen)
		curr = recvBuf[offset:]
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

	if opt.RequestReferenceID.ChunkSize > 0 {
		request := opt.RequestReferenceID
		if request.ChunkOffset+request.ChunkSize > 512 ||
			request.ChunkOffset%4 != 0 ||
			request.ChunkSize%4 != 0 {
			return nil, ErrInvalidReferenceRequest
		}
		writeExtRefIDRequest(buf, opt.RequestReferenceID)
	}

	if opt.RequestSupportedVersions {
		writeExtServerInfo(buf)
	}

	if opt.RequestReferenceTime {
		writeRefTimestamp(buf)
	}

	if opt.RequestMonotonic {
		writeExtMonotonicTimestamp(buf)
	}

	if opt.AdditionalTimescales != nil {
		visited := make(map[Timescale]bool)
		visited[opt.Timescale] = true
		for _, ts := range opt.AdditionalTimescales {
			if !visited[ts] {
				visited[ts] = true
				writeExtSecondaryTimestamp(buf, ts)
			}
		}
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

	// Check for invalid fields in the response message.
	if m.getMode() != responseMode {
		return nil, ErrInvalidMode
	}
	if m.TransmitTime == timestamp(0) {
		return nil, ErrInvalidTransmitTime
	}
	if m.ReceiveTime > m.TransmitTime {
		return nil, ErrServerTickedBackwards
	}
	if m.getVersion() != 5 {
		return nil, ErrInvalidProtocolVersion
	}

	return m, nil
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
