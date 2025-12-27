// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package ntp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"
)

// An timestampV4 is a 64-bit fixed-point (Q32.32) representation of the
// number of seconds elapsed. Used only for NTPv3 and NTPv4 timestamps.
type timestampV4 uint64

// Duration interprets the fixed-point timestampV4 as a number of elapsed
// seconds and returns the corresponding time.Duration value.
func (t timestampV4) Duration() time.Duration {
	sec := (t >> 32) * nanoPerSec
	frac := (t & 0xffffffff) * nanoPerSec
	nsec := frac >> 32
	if uint32(frac) >= 0x80000000 {
		nsec++
	}
	return time.Duration(sec + nsec)
}

// Time interprets the a timestampV4 value as an absolute time and returns the
// corresponding Time value.
func (t timestampV4) Time() time.Time {
	// Assume NTP era 1 (year 2036+) if the raw timestamp suggests a year
	// before 1970. Otherwise assume NTP era 0. This allows the function to
	// report an accurate time value both before and after the 0-to-1 era
	// rollover.
	const t1970 = 0x83aa7e8000000000
	if uint64(t) < t1970 {
		return ntpEra1.Add(t.Duration())
	}
	return ntpEra0.Add(t.Duration())
}

// toTimestampV4 converts a Time value into its 64-bit fixed-point timestampV4
// representation.
func toTimestampV4(t time.Time) timestampV4 {
	nsec := uint64(t.Sub(ntpEra0))
	sec := nsec / nanoPerSec
	remainder := nsec - sec*nanoPerSec
	remainderShifted := remainder << 32
	frac := (remainderShifted + nanoPerSec/2) / nanoPerSec
	return timestampV4(sec<<32 | frac)
}

// An timeShortV4 is a 32-bit fixed-point (Q16.16) representation of the
// number of seconds elapsed. Used only for NTPv3 and NTPv4 "short" times.
type timeShortV4 uint32

// Duration interprets the fixed-point timeShortV4 as a number of elapsed
// seconds and returns the corresponding time.Duration value.
func (t timeShortV4) Duration() time.Duration {
	sec := uint64(t>>16) * nanoPerSec
	frac := uint64(t&0xffff) * nanoPerSec
	nsec := frac >> 16
	if uint16(frac) >= 0x8000 {
		nsec++
	}
	return time.Duration(sec + nsec)
}

// headerV4 is an internal representation of an NTPv3 or NTPv4 packet headerV4.
type headerV4 struct {
	LiVnMode       uint8 // Leap Indicator (2) + Version (3) + Mode (3)
	Stratum        uint8
	Poll           int8
	Precision      int8
	RootDelay      timeShortV4
	RootDispersion timeShortV4
	ReferenceID    uint32 // KoD code if Stratum == 0
	ReferenceTime  timestampV4
	OriginTime     timestampV4
	ReceiveTime    timestampV4
	TransmitTime   timestampV4
}

// setVersion sets the NTP protocol version on the header.
func (h *headerV4) setVersion(v int) {
	h.LiVnMode = (h.LiVnMode & 0xc7) | uint8(v)<<3
}

// setMode sets the NTP protocol mode on the header.
func (h *headerV4) setMode(md mode) {
	h.LiVnMode = (h.LiVnMode & 0xf8) | uint8(md)
}

// setLeap modifies the leap indicator on the header.
func (h *headerV4) setLeap(li LeapIndicator) {
	h.LiVnMode = (h.LiVnMode & 0x3f) | uint8(li)<<6
}

// getVersion returns the version value in the header.
func (h *headerV4) getVersion() int {
	return int((h.LiVnMode >> 3) & 0x7)
}

// getMode returns the mode value in the header.
func (h *headerV4) getMode() mode {
	return mode(h.LiVnMode & 0x07)
}

// getLeap returns the leap indicator on the header.
func (h *headerV4) getLeap() LeapIndicator {
	return LeapIndicator((h.LiVnMode >> 6) & 0x03)
}

// queryV4 performs the NTP server query and returns the response header along
// with the local system time it was received.
func queryV4(conn net.Conn, opt *QueryOptions) (*Response, error) {
	// Allocate a buffer big enough to hold an entire response datagram.
	recvBuf := make([]byte, 8192)
	recvHdr := new(headerV4)

	// Allocate the query message header.
	xmitHdr := new(headerV4)
	xmitHdr.setMode(client)
	xmitHdr.setVersion(opt.Version)
	xmitHdr.setLeap(LeapNoWarning)
	xmitHdr.Precision = 0x20

	// To help prevent spoofing and client fingerprinting, use a
	// cryptographically random 64-bit value for the TransmitTime. See:
	// https://www.ietf.org/archive/id/draft-ietf-ntp-data-minimization-04.txt
	bits := make([]byte, 8)
	_, err := rand.Read(bits)
	if err != nil {
		return nil, err
	}
	xmitHdr.TransmitTime = timestampV4(binary.BigEndian.Uint64(bits))

	// Write the query header to a transmit buffer.
	var xmitBuf bytes.Buffer
	binary.Write(&xmitBuf, binary.BigEndian, xmitHdr)

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

	// Append a MAC if authentication is being used.
	appendMAC(&xmitBuf, opt.Auth, authKey)

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

	// Parse the response header.
	recvBuf = recvBuf[:recvBytes]
	recvReader := bytes.NewReader(recvBuf)
	err = binary.Read(recvReader, binary.BigEndian, recvHdr)
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
	if recvHdr.getMode() != server {
		return nil, ErrInvalidMode
	}
	if recvHdr.TransmitTime == timestampV4(0) {
		return nil, ErrInvalidTransmitTime
	}
	if recvHdr.OriginTime != xmitHdr.TransmitTime {
		return nil, ErrServerResponseMismatch
	}
	if recvHdr.ReceiveTime > recvHdr.TransmitTime {
		return nil, ErrServerTickedBackwards
	}

	// Correct the received message's origin time using the actual
	// transmit time.
	recvHdr.OriginTime = toTimestampV4(xmitTime)

	// Perform authentication of the server response.
	authErr := verifyMAC(recvBuf, opt.Auth, authKey)

	response := generateResponse(recvHdr, toTimestampV4(recvTime), authErr)
	return response, authErr
}

// generateResponse processes NTP header fields along with the its receive
// time to generate a Response record.
func generateResponse(h *headerV4, recvTime timestampV4, authErr error) *Response {
	r := &Response{
		Time:                    h.TransmitTime.Time(),
		ClockOffset:             offset(h.OriginTime, h.ReceiveTime, h.TransmitTime, recvTime),
		RTT:                     rtt(h.OriginTime, h.ReceiveTime, h.TransmitTime, recvTime),
		Precision:               toInterval(h.Precision),
		Version:                 h.getVersion(),
		Stratum:                 h.Stratum,
		ReferenceID:             h.ReferenceID,
		ReferenceTime:           h.ReferenceTime.Time(),
		ReferenceIDFilterValues: nil,
		RootDelay:               h.RootDelay.Duration(),
		RootDispersion:          h.RootDispersion.Duration(),
		Leap:                    h.getLeap(),
		MinError:                minError(h.OriginTime, h.ReceiveTime, h.TransmitTime, recvTime),
		Poll:                    toInterval(h.Poll),
		Flags:                   FlagSynchronized,
		authErr:                 authErr,
	}

	// Calculate values depending on other calculated values
	r.RootDistance = rootDistance(r.RTT, r.RootDelay, r.RootDispersion)

	// If a kiss of death was received, interpret the reference ID as
	// a kiss code.
	if r.Stratum == 0 {
		r.KissCode = kissCode(r.ReferenceID)
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

func rtt(org, rec, xmt, dst timestampV4) time.Duration {
	a := int64(dst - org)
	b := int64(xmt - rec)
	rtt := max(a-b, 0)
	return timestampV4(rtt).Duration()
}

func offset(org, rec, xmt, dst timestampV4) time.Duration {
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
		return -timestampV4(-offset).Duration()
	}
	return timestampV4(offset).Duration()
}

func minError(org, rec, xmt, dst timestampV4) time.Duration {
	// Each NTP response contains two pairs of send/receive timestamps.
	// When either pair indicates a "causality violation", we calculate the
	// error as the difference in time between them. The minimum error is
	// the greater of the two causality violations.
	var error0, error1 timestampV4
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
