// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// This file implements NTP versions 3 and 4 (NTPv3 and NTPv4) protocol
// support.

package ntp

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"net"
	"time"
)

// NTP mode for versions 3 and 4. This package uses only client mode.
type modeV4 uint8

const (
	clientMode modeV4 = 3
	serverMode modeV4 = 4

	// Sentinel value sent in the ReferenceTime field to request whether the
	// server supports NTPv5. If server responds with the same value, then it
	// also supports NTPv5. This value is the ASCII representation of
	// "NTP5DRFT". Once the NTPv5 protocol is finalized, the value will be
	// changed to "NTP5NTP5".
	v5sentinel = 0x4e54503544524654
)

// timeShortV4 is a 32-bit fixed-point (Q16.16) representation of the number
// of seconds elapsed with 15.3us precision.
type timeShortV4 uint32

// Duration interprets the fixed-point timeShortV4 as a number of elapsed
// seconds and returns the corresponding time.Duration value.
func (t timeShortV4) Duration() time.Duration {
	t0 := uint64(t>>16) * nanoPerSec
	f1 := uint64(t&mask16) * nanoPerSec
	t1 := f1 >> 16
	t1 += uint64((f1&mask16)+half16) >> 16 // round half up
	return time.Duration(t0 + t1)
}

// messageV4 is an internal representation of an NTPv3 or NTPv4 message.
type messageV4 struct {
	LiVnMode       uint8 // Leap Indicator (2) + Version (3) + Mode (3)
	Stratum        uint8
	Poll           int8
	Precision      int8
	RootDelay      timeShortV4
	RootDispersion timeShortV4
	ReferenceID    uint32 // KoD code if Stratum == 0
	ReferenceTime  timestamp
	OriginTime     timestamp
	ReceiveTime    timestamp
	TransmitTime   timestamp
}

// setVersion sets the NTP protocol version on the message.
func (m *messageV4) setVersion(v int) {
	m.LiVnMode = (m.LiVnMode & 0xc7) | uint8(v)<<3
}

// setMode sets the NTP protocol mode on the message.
func (m *messageV4) setMode(md modeV4) {
	m.LiVnMode = (m.LiVnMode & 0xf8) | uint8(md)
}

// setLeap modifies the leap indicator on the message.
func (m *messageV4) setLeap(li LeapIndicator) {
	m.LiVnMode = (m.LiVnMode & 0x3f) | uint8(li)<<6
}

// getVersion returns the version value in the message.
func (m *messageV4) getVersion() int {
	return int((m.LiVnMode >> 3) & 0x7)
}

// getMode returns the mode value in the message.
func (m *messageV4) getMode() modeV4 {
	return modeV4(m.LiVnMode & 0x07)
}

// getLeap returns the leap indicator on the message.
func (m *messageV4) getLeap() LeapIndicator {
	return LeapIndicator((m.LiVnMode >> 6) & 0x03)
}

// queryV4 performs the NTPv3 or NTPv4 server query and returns the response
// message along with the local system time it was received.
func queryV4(conn net.Conn, opt *QueryOptions) (*Response, error) {
	// Allocate a buffer big enough to hold an entire response datagram.
	recvBuf := make([]byte, 8192)

	// Allocate a buffer for out-of-band control messages (used to hold
	// hardware timestamps).
	oob := make([]byte, 128)

	// Build the request message.
	xmitBuf, err := buildV4Request(opt)

	// To help prevent spoofing and client fingerprinting, send a random
	// 64-bit value for the TransmitTime and make sure the response includes
	// it in its OriginTime field. See:
	// https://www.ietf.org/archive/id/draft-ietf-ntp-data-minimization-04.txt
	randTimestamp, err := randUint64()
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint64(xmitBuf.Bytes()[40:], randTimestamp)

	// Allow package extensions to process the query and make changes to the
	// transmit buffer.
	for _, e := range opt.Extensions {
		err = e.ProcessQuery(xmitBuf)
		if err != nil {
			return nil, err
		}
	}

	// NTPv3 does not support extension fields.
	if opt.Version == 3 && xmitBuf.Len() > msgSize {
		return nil, ErrExtensionsNotSupported
	}

	// Was symmetric key authentication requested?
	var authKey []byte
	if opt.Auth.Type != AuthNone {
		authKey, err = decodeAuthKey(opt.Auth)
		if err != nil {
			return nil, err
		}

		digest := calcMAC(opt.Version, opt.Auth.Type, authKey, xmitBuf.Bytes())
		binary.Write(xmitBuf, binary.BigEndian, opt.Auth.KeyID)
		binary.Write(xmitBuf, binary.BigEndian, digest)
	}

	// Send the request and keep track of when it was transmitted.
	xmitTime := opt.GetSystemTime()
	_, err = conn.Write(xmitBuf.Bytes())
	if err != nil {
		return nil, err
	}

	// Wait for the response, capturing the kernel-level receive timestamp if
	// possible.
	n, recvTime, err := readWithTimestamp(conn, recvBuf, oob, opt)
	if err != nil {
		return nil, err
	}
	recvBuf = recvBuf[:n]

	// Allow package extensions to process the response buffer.
	for i := len(opt.Extensions) - 1; i >= 0; i-- {
		err = opt.Extensions[i].ProcessResponse(recvBuf)
		if err != nil {
			return nil, err
		}
	}

	// Parse the response message.
	m, err := parseV4Response(recvBuf)
	if err != nil {
		return nil, err
	}

	// Verify that the message's OriginTime matches the random value we sent.
	if m.OriginTime != timestamp(randTimestamp) {
		return nil, ErrServerResponseMismatch
	}

	// Timestamp aliases for readability.
	t1 := xmitTime
	t2 := m.ReceiveTime.TimeV4()
	t3 := m.TransmitTime.TimeV4()
	t4 := recvTime

	// Compose the response struct.
	r := &Response{
		ClockOffset:    offset(t1, t2, t3, t4),
		RTT:            rtt(t1, t2, t3, t4),
		Timestamps:     ProtocolTimestamps{t1, t2, t3, t4},
		Precision:      toInterval(m.Precision),
		Version:        m.getVersion(),
		Stratum:        m.Stratum,
		Era:            inferEra(m.TransmitTime),
		Timescale:      TimescaleUTC,
		ReferenceID:    m.ReferenceID,
		ReferenceTime:  m.ReferenceTime.TimeV4(),
		RootDelay:      m.RootDelay.Duration(),
		RootDispersion: m.RootDispersion.Duration(),
		Leap:           m.getLeap(),
		MinError:       minError(t1, t2, t3, t4),
		Poll:           toInterval(m.Poll),
		Flags:          0,
		Time:           m.TransmitTime.TimeV4(),
	}

	// If supported versions were requested, check the response for an answer.
	if opt.RequestSupportedVersions {
		// Always include the version used in the query.
		r.SupportedVersions = []int{opt.Version}

		// If the server responded to the NTPv5 support request in its
		// ReferenceTime field, add version 5 to the list and invalidate the
		// ReferenceTime.
		if m.ReferenceTime == v5sentinel {
			r.SupportedVersions = append(r.SupportedVersions, 5)
			r.ReferenceTime = ntpEra0
		}
	}

	// Calculate root distance.
	r.RootDistance = rootDistance(r.RTT, r.RootDelay, r.RootDispersion)

	// If a kiss of death was received, interpret the reference ID as
	// a kiss code.
	if r.Stratum == 0 {
		r.KissCode = kissCode(r.ReferenceID)
	}

	// Responses with valid stratum values are considered synchronized.
	if r.Stratum > 1 && r.Stratum < maxStratum {
		r.Flags |= FlagSynchronized
	}

	// If symmetric authentication was requested, authenticate the response.
	if opt.Auth.Type != AuthNone {
		r.authErr = verifyMAC(recvBuf, opt, authKey)
	}

	return r, r.authErr
}

// buildV4Request creates an NTPv3 or NTPv4 request message.
func buildV4Request(opt *QueryOptions) (*bytes.Buffer, error) {
	// Build the NTPv4 message.
	m := messageV4{}
	m.setVersion(opt.Version)
	m.setMode(clientMode)
	m.setLeap(LeapNoWarning)

	// To request whether the server supports NTPv5, set the reference time to
	// "NTP5DRFT". If the server supports it, it will echo this value back.
	if opt.RequestSupportedVersions {
		m.ReferenceTime = v5sentinel
	}

	// Write the message to a buffer.
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, m.LiVnMode)
	binary.Write(buf, binary.BigEndian, m.Stratum)
	binary.Write(buf, binary.BigEndian, m.Poll)
	binary.Write(buf, binary.BigEndian, m.Precision)
	binary.Write(buf, binary.BigEndian, m.RootDelay)
	binary.Write(buf, binary.BigEndian, m.RootDispersion)
	binary.Write(buf, binary.BigEndian, m.ReferenceID)
	binary.Write(buf, binary.BigEndian, m.ReferenceTime)
	binary.Write(buf, binary.BigEndian, m.OriginTime)
	binary.Write(buf, binary.BigEndian, m.ReceiveTime)
	binary.Write(buf, binary.BigEndian, m.TransmitTime)

	return buf, nil
}

// parseV4Response parses an NTPv3 or NTPv4 response message from a buffer.
func parseV4Response(data []byte) (*messageV4, error) {
	if len(data) < msgSize {
		return nil, ErrInvalidTime
	}

	m := &messageV4{}
	r := bytes.NewReader(data)
	binary.Read(r, binary.BigEndian, &m.LiVnMode)
	binary.Read(r, binary.BigEndian, &m.Stratum)
	binary.Read(r, binary.BigEndian, &m.Poll)
	binary.Read(r, binary.BigEndian, &m.Precision)
	binary.Read(r, binary.BigEndian, &m.RootDelay)
	binary.Read(r, binary.BigEndian, &m.RootDispersion)
	binary.Read(r, binary.BigEndian, &m.ReferenceID)
	binary.Read(r, binary.BigEndian, &m.ReferenceTime)
	binary.Read(r, binary.BigEndian, &m.OriginTime)
	binary.Read(r, binary.BigEndian, &m.ReceiveTime)
	binary.Read(r, binary.BigEndian, &m.TransmitTime)

	// Check for invalid fields.
	if m.getMode() != serverMode {
		return nil, ErrInvalidMode
	}
	if m.TransmitTime == timestamp(0) {
		return nil, ErrInvalidTransmitTime
	}
	if m.ReceiveTime > m.TransmitTime {
		return nil, ErrServerTickedBackwards
	}

	return m, nil
}

func verifyMAC(buf []byte, opt *QueryOptions, key []byte) error {
	// Check for a trailing crypto-NAK (with no extension fields). Modern NTP
	// servers no longer send crypto-NAKs, but some older ones do.
	remain := len(buf) - msgSize
	if opt.Version == 4 && remain == 4 {
		if binary.BigEndian.Uint32(buf[len(buf)-4:]) == 0 {
			return ErrAuthNAK
		}
	}

	// Validate that there are enough bytes at the end of the message to
	// contain a complete MAC for the hash algorithm.
	macLen := 4 + getMACSize(opt.Version, opt.Auth.Type)
	if remain < macLen || (remain%4) != 0 {
		return ErrAuthFailed
	}

	// The key ID returned by the server must be the same as the key ID sent
	// to the server.
	payloadLen := len(buf) - macLen
	mac := buf[payloadLen:]
	keyID := binary.BigEndian.Uint32(mac[:4])
	if keyID != opt.Auth.KeyID {
		return ErrAuthFailed
	}

	// Calculate and compare digests.
	payload := buf[:payloadLen]
	digestRecv := mac[4:]
	digestCalc := calcMAC(opt.Version, opt.Auth.Type, key, payload)
	if subtle.ConstantTimeCompare(digestCalc, digestRecv) == 0 {
		return ErrAuthFailed
	}

	return nil
}

func kissCode(id uint32) string {
	isPrintable := func(ch byte) bool { return ch >= 32 && ch <= 126 }

	b := [4]byte{
		byte(id >> 24),
		byte(id >> 16),
		byte(id >> 8),
		byte(id),
	}
	for _, ch := range b {
		if !isPrintable(ch) {
			return ""
		}
	}
	return string(b[:])
}
