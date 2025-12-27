// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ntp

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"net"
	"time"
)

// NTP mode for versions 3 and 4. This package uses only client mode.
type modeV4 uint8

const (
	reserved modeV4 = 0 + iota
	symmetricActive
	symmetricPassive
	client
	server
	broadcast
	controlMessage
	reservedPrivate
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

// queryV4 performs the NTP server query and returns the response message
// along with the local system time it was received.
func queryV4(conn net.Conn, opt *QueryOptions) (*Response, error) {
	// Allocate a buffer big enough to hold an entire response datagram.
	recvBuf := make([]byte, 8192)
	recvMsg := new(messageV4)

	// Allocate the query message message.
	xmitMsg := new(messageV4)
	xmitMsg.setMode(client)
	xmitMsg.setVersion(opt.Version)
	xmitMsg.setLeap(LeapNoWarning)
	xmitMsg.Precision = 0x20

	// To help prevent spoofing and client fingerprinting, use a
	// cryptographically random 64-bit value for the TransmitTime. See:
	// https://www.ietf.org/archive/id/draft-ietf-ntp-data-minimization-04.txt
	bits := make([]byte, 8)
	_, err := rand.Read(bits)
	if err != nil {
		return nil, err
	}
	xmitMsg.TransmitTime = timestamp(binary.BigEndian.Uint64(bits))

	// Write the query message to a transmit buffer.
	var xmitBuf bytes.Buffer
	binary.Write(&xmitBuf, binary.BigEndian, xmitMsg)

	// Allow extensions to process the query and add to the transmit buffer.
	for _, e := range opt.Extensions {
		err = e.ProcessQuery(&xmitBuf)
		if err != nil {
			return nil, err
		}
	}

	// If using symmetric key authentication, decode and validate the auth key
	// string.
	authKey, err := decodeAuthKey(opt.Auth)
	if err != nil {
		return nil, err
	}

	// Append a MAC if symmetric authentication is being used.
	if opt.Auth.Type != AuthNone {
		digest := calcMAC(xmitBuf.Bytes(), opt.Auth.Type, authKey)
		binary.Write(&xmitBuf, binary.BigEndian, opt.Auth.KeyID)
		binary.Write(&xmitBuf, binary.BigEndian, digest)
	}

	// Transmit the query and keep track of when it was transmitted.
	xmitTime := opt.GetSystemTime()
	_, err = conn.Write(xmitBuf.Bytes())
	if err != nil {
		return nil, err
	}

	// Receive the response.
	recvBytes, err := conn.Read(recvBuf)
	if err != nil {
		return nil, err
	}

	// Keep track of the time the response was received. As of go 1.9, the
	// time package uses a monotonic clock, so delta will never be less than
	// zero for go version 1.9 or higher.
	recvTime := opt.GetSystemTime()
	if recvTime.Sub(xmitTime) < 0 {
		recvTime = xmitTime
	}

	// Parse the response message.
	recvBuf = recvBuf[:recvBytes]
	recvReader := bytes.NewReader(recvBuf)
	err = binary.Read(recvReader, binary.BigEndian, recvMsg)
	if err != nil {
		return nil, err
	}

	// Allow extensions to process the response.
	for i := len(opt.Extensions) - 1; i >= 0; i-- {
		err = opt.Extensions[i].ProcessResponse(recvBuf)
		if err != nil {
			return nil, err
		}
	}

	// Check for invalid fields.
	if recvMsg.getMode() != server {
		return nil, ErrInvalidMode
	}
	if recvMsg.TransmitTime == timestamp(0) {
		return nil, ErrInvalidTransmitTime
	}
	if recvMsg.OriginTime != xmitMsg.TransmitTime {
		return nil, ErrServerResponseMismatch
	}
	if recvMsg.ReceiveTime > recvMsg.TransmitTime {
		return nil, ErrServerTickedBackwards
	}

	// Correct the received message's origin time using the actual
	// transmit time.
	recvMsg.OriginTime = toTimestamp(xmitTime)

	// Perform symmetric authentication of the response.
	var authErr error
	if opt.Auth.Type != AuthNone {
		authErr = verifyMAC(recvBuf, opt.Auth, authKey)
	}

	response := generateResponse(recvMsg, toTimestamp(recvTime), authErr)
	return response, authErr
}

func verifyMAC(buf []byte, opt AuthOptions, key []byte) error {
	// Validate that there are enough bytes at the end of the message to
	// contain a MAC.
	macLen := 4 + getMACSize(opt.Type)
	remain := len(buf) - msgSize
	if remain < macLen || (remain%4) != 0 {
		return ErrAuthFailed
	}

	// The key ID returned by the server must be the same as the key ID sent
	// to the server.
	payloadLen := len(buf) - macLen
	mac := buf[payloadLen:]
	keyID := binary.BigEndian.Uint32(mac[:4])
	if keyID != opt.KeyID {
		return ErrAuthFailed
	}

	// Calculate and compare digests.
	payload := buf[:payloadLen]
	digestRecv := mac[4:]
	digestCalc := calcMAC(payload, opt.Type, key)
	if subtle.ConstantTimeCompare(digestCalc, digestRecv) == 0 {
		return ErrAuthFailed
	}

	return nil
}

// generateResponse processes NTP message fields along with the the receive
// time to generate a Response record.
func generateResponse(m *messageV4, recvTime timestamp, authErr error) *Response {
	r := &Response{
		Time:                    m.TransmitTime.TimeV4(),
		ClockOffset:             offset(m.OriginTime, m.ReceiveTime, m.TransmitTime, recvTime),
		RTT:                     rtt(m.OriginTime, m.ReceiveTime, m.TransmitTime, recvTime),
		Precision:               toInterval(m.Precision),
		Version:                 m.getVersion(),
		Stratum:                 m.Stratum,
		ReferenceID:             m.ReferenceID,
		ReferenceTime:           m.ReferenceTime.TimeV4(),
		ReferenceIDFilterValues: nil,
		RootDelay:               m.RootDelay.Duration(),
		RootDispersion:          m.RootDispersion.Duration(),
		Leap:                    m.getLeap(),
		MinError:                minError(m.OriginTime, m.ReceiveTime, m.TransmitTime, recvTime),
		Poll:                    toInterval(m.Poll),
		Flags:                   0,
		authErr:                 authErr,
	}

	// Calculate values depending on other calculated values
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

	return r
}

// The following helper functions calculate additional metadata about the
// timestamps received from an NTP server.  The timestamps returned by
// the server are given the following variable names:
//
//   org = Origin Timestamp (client send time)
//   rec = Receive Timestamp (server receive time)
//   xmt = Transmit Timestamp (server reply time)
//   dst = Destination Timestamp (client receive time)

func rtt(org, rec, xmt, dst timestamp) time.Duration {
	a := int64(dst - org)
	b := int64(xmt - rec)
	rtt := max(a-b, 0)
	return timestamp(rtt).Duration()
}

func offset(org, rec, xmt, dst timestamp) time.Duration {
	// The inputs are 64-bit unsigned integer timestamps. These timestamps can
	// "roll over" at the end of an NTP era, which occurs approximately every
	// 136 years starting from the year 1900. To ensure an accurate offset
	// calculation when an era boundary is crossed, we need to take care that
	// the difference between two 64-bit timestamp values is accurately
	// calculated even when they are in neighboring eras.
	//
	// See: https://www.eecis.udel.edu/~mills/y2k.html

	a := int64(rec - org)
	b := int64(xmt - dst)
	offset := a + (b-a)/2
	if offset < 0 {
		return -timestamp(-offset).Duration()
	}
	return timestamp(offset).Duration()
}

func minError(org, rec, xmt, dst timestamp) time.Duration {
	// Each NTP response contains two pairs of send/receive timestamps.
	// When either pair indicates a "causality violation", we calculate the
	// error as the difference in time between them. The minimum error is
	// the greater of the two causality violations.
	var error0, error1 timestamp
	if org >= rec {
		error0 = org - rec
	}
	if xmt >= dst {
		error1 = xmt - dst
	}
	if error0 > error1 {
		return error0.Duration()
	}
	return error1.Duration()
}

func rootDistance(rtt, rootDelay, rootDisp time.Duration) time.Duration {
	// The root distance is:
	// 	the maximum error due to all causes of the local clock
	//	relative to the primary server. It is defined as half the
	//	total delay plus total dispersion plus peer jitter.
	//	(https://tools.ietf.org/html/rfc5905#appendix-A.5.5.2)
	//
	// In the reference implementation, it is calculated as follows:
	//	rootDist = max(MINDISP, rootDelay + rtt)/2 + rootDisp
	//			+ peerDisp + PHI * (uptime - peerUptime)
	//			+ peerJitter
	// For an SNTP client which sends only a single packet, most of these
	// terms are irrelevant and become 0.
	totalDelay := rtt + rootDelay
	return totalDelay/2 + rootDisp
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
