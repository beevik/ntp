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
	draftID = "draft-ietf-ntp-ntpv5-06"
)

// timestamp64 is a 64-bit fixed-point (Q32.32) type describing a timestamp
// specified in seconds.
type timestamp64 uint64

// Duration interprets a timestamp64 value as a time duration.
func (t timestamp64) Duration() time.Duration {
	sec := (uint64(t) >> 32) * nanoPerSec
	frac := (uint64(t) & 0xffffffff) * nanoPerSec
	nsec := frac >> 32
	if uint32(frac) >= 0x80000000 {
		nsec++
	}
	return time.Duration(sec + nsec)
}

// Time interprets a timestamp64 value as an absolute time, using the provided
// era number to disambiguate the time period.
func (t timestamp64) Time(era uint8) time.Time {
	var eraStart time.Time
	if era == 0 {
		eraStart = ntpEra0
	} else {
		eraOffset := time.Duration(uint64(era) * (1 << 32) * uint64(time.Second))
		eraStart = ntpEra0.Add(eraOffset)
	}
	return eraStart.Add(t.Duration())
}

// getEra determines the NTP era for the provided time.
func getEra(t time.Time) uint8 {
	ntpSec := uint64(t.Unix() - ntpEra0.Unix())
	return uint8(ntpSec >> 32)
}

// toTimestamp64 converts a Time value to a timestamp64 representation,
// inferring the era from the time.
func toTimestamp64(t time.Time) timestamp64 {
	var eraStart time.Time
	era := getEra(t)
	if era == 0 {
		eraStart = ntpEra0
	} else {
		eraOffset := time.Duration(uint64(era) * uint64(time.Second) * (1 << 32))
		eraStart = ntpEra0.Add(eraOffset)
	}

	nsec := uint64(t.Sub(eraStart))
	sec := nsec / nanoPerSec
	if sec > 0xffffffff {
		return timestamp64(0xffffffff_ffffffff)
	}

	remainder := nsec - sec*nanoPerSec
	remainderShifted := remainder << 32
	frac := (remainderShifted + nanoPerSec/2) / nanoPerSec
	return timestamp64(sec<<32 | frac)
}

// time32 is a 32-bit fixed-point (Q4.28) type describing a time duration in
// seconds.
type time32 uint32

// Duration converts a time32 value to a Duration value.
func (t time32) Duration() time.Duration {
	sec := uint64(t>>28) * nanoPerSec
	frac := uint64(t&0x0fffffff) * nanoPerSec
	nsec := frac >> 28
	if frac >= 0x08000000 {
		nsec++
	}
	return time.Duration(sec + nsec)
}

// toTime32 converts a Duration to a fixed-point time32 representation.
func toTime32(d time.Duration) time32 {
	if d <= 0 {
		return 0
	}

	nsec := uint64(d)
	sec := nsec / nanoPerSec
	if sec > 15 {
		return 0xffffffff
	}

	remainder := nsec - sec*nanoPerSec
	remainderShifted := remainder << 28
	frac := (remainderShifted + nanoPerSec/2) / nanoPerSec
	return time32((sec << 28) | frac)
}

// headerV5 is an internal representation of an NTPv5 packet header.
type headerV5 struct {
	LiVnMode     uint8 // Leap Indicator (2) + Version (3) + Mode (3)
	Stratum      uint8
	Poll         int8
	Precision    int8
	RootDelay    time32
	RootDisp     time32
	Timescale    uint8
	Era          uint8
	Flags        uint16
	ServerCookie uint64
	ClientCookie uint64
	ReceiveTime  timestamp64
	TransmitTime timestamp64
}

// NTPv5 flag values.
const (
	flagSynchronized = 1 << 0
	flagInterleaved  = 1 << 1
	flagAuthNAK      = 1 << 2
)

// setVersion sets the NTP protocol version on the header.
func (h *headerV5) setVersion(v int) {
	h.LiVnMode = (h.LiVnMode & 0xc7) | uint8(v)<<3
}

// setMode sets the NTP protocol mode on the header.
func (h *headerV5) setMode(md mode) {
	h.LiVnMode = (h.LiVnMode & 0xf8) | uint8(md)
}

// setLeap modifies the leap indicator on the header.
func (h *headerV5) setLeap(li LeapIndicator) {
	h.LiVnMode = (h.LiVnMode & 0x3f) | uint8(li)<<6
}

// getVersion returns the version value in the header.
func (h *headerV5) getVersion() int {
	return int((h.LiVnMode >> 3) & 0x7)
}

// getMode returns the mode value in the header.
func (h *headerV5) getMode() mode {
	return mode(h.LiVnMode & 0x07)
}

// getLeap returns the leap indicator on the header.
func (h *headerV5) getLeap() LeapIndicator {
	return LeapIndicator((h.LiVnMode >> 6) & 0x03)
}

// parseV5Header parses the NTPv5 header from a buffer.
func parseV5Header(data []byte) (*headerV5, error) {
	if len(data) < ntpHeaderSize {
		return nil, ErrInvalidTime
	}

	h := &headerV5{}
	r := bytes.NewReader(data)

	binary.Read(r, binary.BigEndian, &h.LiVnMode)
	binary.Read(r, binary.BigEndian, &h.Stratum)
	binary.Read(r, binary.BigEndian, &h.Poll)
	binary.Read(r, binary.BigEndian, &h.Precision)
	binary.Read(r, binary.BigEndian, &h.RootDelay)
	binary.Read(r, binary.BigEndian, &h.RootDisp)
	binary.Read(r, binary.BigEndian, &h.Timescale)
	binary.Read(r, binary.BigEndian, &h.Era)
	binary.Read(r, binary.BigEndian, &h.Flags)
	binary.Read(r, binary.BigEndian, &h.ServerCookie)
	binary.Read(r, binary.BigEndian, &h.ClientCookie)
	binary.Read(r, binary.BigEndian, &h.ReceiveTime)
	binary.Read(r, binary.BigEndian, &h.TransmitTime)

	return h, nil
}

// queryV5 performs an NTPv5 time query using the provided connection.
func queryV5(conn net.Conn, opt *QueryOptions) (*Response, error) {
	// Generate a random client cookie.
	var cookieBytes [8]byte
	_, err := rand.Read(cookieBytes[:])
	if err != nil {
		return nil, err
	}
	clientCookie := binary.BigEndian.Uint64(cookieBytes[:])

	// Decode the authentication key if symmetric key authentication has been
	// requested.
	authKey, err := decodeAuthKey(opt.Auth)
	if err != nil {
		return nil, err
	}

	// Build the request datagram.
	xmitBuf, err := buildV5Request(opt, clientCookie, authKey)
	if err != nil {
		return nil, err
	}

	// Allocate a buffer big enough to hold an entire response datagram.
	recvBuf := make([]byte, 8192)

	// Send the request.
	clientXmitTime := opt.GetSystemTime()
	_, err = conn.Write(xmitBuf.Bytes())
	if err != nil {
		return nil, err
	}

	// Receive the response.
	n, err := conn.Read(recvBuf)
	if err != nil {
		return nil, err
	}

	// Keep track of the time the response was received.
	clientRecvTime := opt.GetSystemTime()

	// Parse the response header.
	recvBuf = recvBuf[:n]
	h, err := parseV5Header(recvBuf)
	if err != nil {
		return nil, err
	}

	// Process extension fields.
	var authErr error
	var refIDFilter []byte
	offset := ntpHeaderSize
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
			if len(curr) != xlen {
				return nil, ErrMACExtensionNotAtEnd
			}
			mac := calcMAC(recvBuf[:offset], opt.Auth.Type, authKey)
			if subtle.ConstantTimeCompare(mac, body[4:]) != 1 {
				authErr = ErrAuthFailed
			}

		case extRefIDResp:
			refIDFilter = body

		case extDraftID:
			if len(body) != paddedLen(len(draftID)) {
				return nil, ErrInvalidDraftID
			}
			if string(body[:len(draftID)]) != draftID {
				return nil, ErrInvalidDraftID
			}
		}

		offset += xlen
		curr = recvBuf[offset:]
	}

	// Allow extensions to process the response.
	for i := len(opt.Extensions) - 1; i >= 0; i-- {
		err = opt.Extensions[i].ProcessResponse(recvBuf)
		if err != nil {
			return nil, err
		}
	}

	// Check for invalid fields.
	if h.getMode() != server {
		return nil, ErrInvalidMode
	}
	if h.getVersion() != 5 {
		return nil, ErrInvalidProtocolVersion
	}
	if h.ClientCookie != clientCookie {
		return nil, ErrServerResponseMismatch
	}

	// Check for authentication NAK.
	if h.Flags&flagAuthNAK != 0 {
		authErr = ErrAuthNAK
	}

	// Convert timestamps.
	serverRecvTime := timestamp64(h.ReceiveTime).Time(h.Era)
	serverXmitTime := timestamp64(h.TransmitTime).Time(h.Era)

	// Calculate clock offset and RTT.
	// offset = ((t2 - t1) + (t3 - t4)) / 2
	// rtt = (t4 - t1) - (t3 - t2)
	t1 := clientXmitTime
	t2 := serverRecvTime
	t3 := serverXmitTime
	t4 := clientRecvTime
	clockOffset := (t2.Sub(t1) + t3.Sub(t4)) / 2
	rtt := max(t4.Sub(t1)-t3.Sub(t2), 0)

	// Calculate root dispersion and distance.
	rootDelay := h.RootDelay.Duration()
	rootDisp := h.RootDisp.Duration()
	rootDistance := (rtt+rootDelay)/2 + rootDisp

	// Calculate min error (causality violation detection).
	var minError time.Duration
	if t2.Before(t1) || t4.Before(t3) {
		minError = max(t1.Sub(t2), t3.Sub(t4))
	}

	// Determine response flags.
	var flags ResponseFlags
	if h.Flags&flagSynchronized != 0 {
		flags |= FlagSynchronized
	}
	if h.Flags&flagInterleaved != 0 {
		flags |= FlagInterleaved
	}

	// Build the response.
	r := &Response{
		ClockOffset:             clockOffset,
		Time:                    serverXmitTime,
		RTT:                     rtt,
		Precision:               toInterval(h.Precision),
		Version:                 5,
		Stratum:                 h.Stratum,
		ReferenceID:             0,           // not used in NTPv5
		ReferenceTime:           time.Time{}, // not used in NTPv5
		ReferenceIDFilterValues: refIDFilter,
		RootDelay:               rootDelay,
		RootDispersion:          rootDisp,
		RootDistance:            rootDistance,
		Leap:                    h.getLeap(),
		MinError:                minError,
		KissCode:                "", // not used in NTPv5
		Poll:                    toInterval(h.Poll),
		Timescale:               Timescale(h.Timescale),
		Era:                     h.Era,
		Flags:                   flags,
		ServerCookie:            h.ServerCookie,
		authErr:                 authErr,
	}
	return r, authErr
}

// buildV5Request creates an NTPv5 request packet.
func buildV5Request(opt *QueryOptions, clientCookie uint64, authKey []byte) (*bytes.Buffer, error) {
	// Build the NTPv5 header.
	h := &headerV5{
		Precision:    0x20,
		Timescale:    uint8(opt.Timescale),
		Era:          0, // always 0 for requests
		ClientCookie: clientCookie,
	}
	h.setVersion(5)
	h.setMode(client)
	h.setLeap(LeapNotInSync)

	// Write the header to a buffer.
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, h.LiVnMode)
	binary.Write(buf, binary.BigEndian, h.Stratum)
	binary.Write(buf, binary.BigEndian, h.Poll)
	binary.Write(buf, binary.BigEndian, h.Precision)
	binary.Write(buf, binary.BigEndian, h.RootDelay)
	binary.Write(buf, binary.BigEndian, h.RootDisp)
	binary.Write(buf, binary.BigEndian, h.Timescale)
	binary.Write(buf, binary.BigEndian, h.Era)
	binary.Write(buf, binary.BigEndian, h.Flags)
	binary.Write(buf, binary.BigEndian, h.ServerCookie)
	binary.Write(buf, binary.BigEndian, h.ClientCookie)
	binary.Write(buf, binary.BigEndian, h.ReceiveTime)
	binary.Write(buf, binary.BigEndian, h.TransmitTime)

	// Append the experimental draft id extension field. This will be removed
	// once NTPv5 is finalized.
	writeExtDraftID(buf)

	// Append the reference ID request if necessary.
	if opt.RequestReferenceIDFilter.ChunkSize > 0 {
		if opt.RequestReferenceIDFilter.ChunkOffset+opt.RequestReferenceIDFilter.ChunkSize > 512 {
			return nil, ErrInvalidReferenceRequest
		}
		writeExtRefIDRequest(buf, opt.RequestReferenceIDFilter)
	}

	// Allow package extensions to process the query and modify the transmit
	// buffer.
	for _, e := range opt.Extensions {
		err := e.ProcessQuery(buf)
		if err != nil {
			return nil, err
		}
	}

	// Append a MAC extension field if symmetric key authentication is
	// requested. This must be the last extension field.
	if authKey != nil {
		payload := buf.Bytes()
		mac := calcMAC(payload, opt.Auth.Type, authKey)
		writeExtMAC(buf, opt.Auth, mac)
	}

	return buf, nil
}

func writeExtRefIDRequest(buf *bytes.Buffer, req ReferenceIDFilterRequest) {
	binary.Write(buf, binary.BigEndian, extRefIDReq)
	binary.Write(buf, binary.BigEndian, req.ChunkSize+4)
	binary.Write(buf, binary.BigEndian, req.ChunkOffset)
	buf.Write(make([]byte, req.ChunkSize-4))
}

func writeExtMAC(buf *bytes.Buffer, opt AuthOptions, mac []byte) {
	binary.Write(buf, binary.BigEndian, extMAC)
	binary.Write(buf, binary.BigEndian, uint16(4+len(mac)))
	binary.Write(buf, binary.BigEndian, uint32(opt.KeyID))
	buf.Write(mac)
}

func writeExtDraftID(buf *bytes.Buffer) {
	valueLenPadded := paddedLen(len(draftID))
	totalLen := 4 + valueLenPadded

	binary.Write(buf, binary.BigEndian, extDraftID)
	binary.Write(buf, binary.BigEndian, uint16(totalLen))
	buf.Write([]byte(draftID))
	buf.Write(padBytes[:valueLenPadded-len(draftID)])
}

var padBytes = make([]byte, 4)

func paddedLen(len int) int {
	return (len + 3) & ^3
}
