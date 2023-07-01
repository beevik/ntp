// Copyright 2015-2023 Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ntp provides an implementation of a Simple NTP (SNTP) client
// capable of querying the current time from a remote NTP server.  See
// RFC5905 (https://tools.ietf.org/html/rfc5905) for more details.
//
// This approach grew out of a go-nuts post by Michael Hofmann:
// https://groups.google.com/forum/?fromgroups#!topic/golang-nuts/FlcdMU5fkLQ
package ntp

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"golang.org/x/net/ipv4"
)

// The LeapIndicator is used to warn if a leap second should be inserted
// or deleted in the last minute of the current month.
type LeapIndicator uint8

const (
	// LeapNoWarning indicates no impending leap second.
	LeapNoWarning LeapIndicator = 0

	// LeapAddSecond indicates the last minute of the day has 61 seconds.
	LeapAddSecond = 1

	// LeapDelSecond indicates the last minute of the day has 59 seconds.
	LeapDelSecond = 2

	// LeapNotInSync indicates an unsynchronized leap second.
	LeapNotInSync = 3
)

// Internal constants
const (
	defaultNtpVersion = 4
	nanoPerSec        = 1000000000
	maxStratum        = 16
	defaultTimeout    = 5 * time.Second
	maxPollInterval   = (1 << 17) * time.Second
	maxDispersion     = 16 * time.Second
)

var ErrNotSupportCryptoMethod = errors.New("Not Support Crypto Method , only support md5, sha1, sha256, sha512")

// Internal variables
var (
	ntpEpoch = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
)

type mode uint8

// NTP modes. This package uses only client mode.
const (
	reserved mode = 0 + iota
	symmetricActive
	symmetricPassive
	client
	server
	broadcast
	controlMessage
	reservedPrivate
)

const (
	CryptoMd5 = 1 << iota
	CryptoSha1
	CryptoSha256
	CryptoSha512
)

// An ntpTime is a 64-bit fixed-point (Q32.32) representation of the number of
// seconds elapsed.
type ntpTime uint64

// Duration interprets the fixed-point ntpTime as a number of elapsed seconds
// and returns the corresponding time.Duration value.
func (t ntpTime) Duration() time.Duration {
	sec := (t >> 32) * nanoPerSec
	frac := (t & 0xffffffff) * nanoPerSec
	nsec := frac >> 32
	if uint32(frac) >= 0x80000000 {
		nsec++
	}
	return time.Duration(sec + nsec)
}

// Time interprets the fixed-point ntpTime as an absolute time and returns
// the corresponding time.Time value.
func (t ntpTime) Time() time.Time {
	return ntpEpoch.Add(t.Duration())
}

// toNtpTime converts the time.Time value t into its 64-bit fixed-point
// ntpTime representation.
func toNtpTime(t time.Time) ntpTime {
	nsec := uint64(t.Sub(ntpEpoch))
	sec := nsec / nanoPerSec
	nsec = uint64(nsec-sec*nanoPerSec) << 32
	frac := uint64(nsec / nanoPerSec)
	if nsec%nanoPerSec >= nanoPerSec/2 {
		frac++
	}
	return ntpTime(sec<<32 | frac)
}

// An ntpTimeShort is a 32-bit fixed-point (Q16.16) representation of the
// number of seconds elapsed.
type ntpTimeShort uint32

// Duration interprets the fixed-point ntpTimeShort as a number of elapsed
// seconds and returns the corresponding time.Duration value.
func (t ntpTimeShort) Duration() time.Duration {
	sec := uint64(t>>16) * nanoPerSec
	frac := uint64(t&0xffff) * nanoPerSec
	nsec := frac >> 16
	if uint16(frac) >= 0x8000 {
		nsec++
	}
	return time.Duration(sec + nsec)
}

// msg is an internal representation of an NTP packet.
type msg struct {
	LiVnMode       uint8 // Leap Indicator (2) + Version (3) + Mode (3)
	Stratum        uint8
	Poll           int8
	Precision      int8
	RootDelay      ntpTimeShort
	RootDispersion ntpTimeShort
	ReferenceID    uint32
	ReferenceTime  ntpTime
	OriginTime     ntpTime
	ReceiveTime    ntpTime
	TransmitTime   ntpTime
}

type Authentication struct {
	KeyID          uint32 // key id
	CryptoMethod   int    // only support md5 and sha1
	Authentication string // the crypto string
}

// setVersion sets the NTP protocol version on the message.
func (m *msg) setVersion(v int) {
	m.LiVnMode = (m.LiVnMode & 0xc7) | uint8(v)<<3
}

// setMode sets the NTP protocol mode on the message.
func (m *msg) setMode(md mode) {
	m.LiVnMode = (m.LiVnMode & 0xf8) | uint8(md)
}

// setLeap modifies the leap indicator on the message.
func (m *msg) setLeap(li LeapIndicator) {
	m.LiVnMode = (m.LiVnMode & 0x3f) | uint8(li)<<6
}

// getMode returns the mode value in the message.
func (m *msg) getMode() mode {
	return mode(m.LiVnMode & 0x07)
}

// getLeap returns the leap indicator on the message.
func (m *msg) getLeap() LeapIndicator {
	return LeapIndicator((m.LiVnMode >> 6) & 0x03)
}

// dialFn is a function used to override the QueryWithOptions function's
// default network "dialing" behavior. It creates a connection to a remote
// network endpoint (raddr + rport) from a local network endpoint (laddr +
// lport). The local address 'laddr' comes from the 'LocalAddress' specified
// in QueryOptions. The local port 'lport' is always zero. The remote address
// 'raddr' comes from the QueryWithOptions host parameter. The remote port
// 'rport' comes from the 'Port' specified in QueryOptions.
type dialFn func(laddr string, lport int, raddr string, rport int) (net.Conn, error)

// QueryOptions contains configurable options used by the QueryWithOptions
// function.
type QueryOptions struct {
	Timeout        time.Duration  // connection timeout, defaults to 5 seconds
	Version        int            // NTP protocol version, defaults to 4
	LocalAddress   string         // address to use for the local system
	Port           int            // remote server port, defaults to 123
	TTL            int            // IP TTL to use, defaults to system default
	Dial           dialFn         // overrides the default UDP dialer
	authentication Authentication // ntp auth
	needAuth       bool           // is need auth
}

func (q *QueryOptions) EnableAuthentication(authentication Authentication) {
	q.needAuth = true
	q.authentication = authentication
}

// A Response contains time data, some of which is returned by the NTP server
// and some of which is calculated by this client.
type Response struct {
	// Time is the transmit time reported by the server just before it
	// responded to the client's NTP query.
	Time time.Time

	// ClockOffset is the estimated offset of the local system clock relative
	// to the server's clock. Add this value to subsequent local system time
	// measurements in order to obtain a more accurate time.
	ClockOffset time.Duration

	// RTT is the measured round-trip-time delay estimate between the client
	// and the server.
	RTT time.Duration

	// Precision is the reported precision of the server's clock.
	Precision time.Duration

	// Stratum is the "stratum level" of the server. The smaller the number,
	// the closer the server is to the reference clock. Stratum 1 servers are
	// attached directly to the reference clock. A stratum value of 0
	// indicates the "kiss of death," which typically occurs when the client
	// issues too many requests to the server in a short period of time.
	Stratum uint8

	// ReferenceID is a 32-bit identifier identifying the server or
	// reference clock.
	ReferenceID uint32

	// ReferenceTime is the time when the server's system clock was last
	// set or corrected.
	ReferenceTime time.Time

	// RootDelay is the server's estimated aggregate round-trip-time delay to
	// the stratum 1 server.
	RootDelay time.Duration

	// RootDispersion is the server's estimated maximum measurement error
	// relative to the stratum 1 server.
	RootDispersion time.Duration

	// RootDistance is an estimate of the total synchronization distance
	// between the client and the stratum 1 server.
	RootDistance time.Duration

	// Leap indicates whether a leap second should be added or removed from
	// the current month's last minute.
	Leap LeapIndicator

	// MinError is a lower bound on the error between the client and server
	// clocks. When the client and server are not synchronized to the same
	// clock, the reported timestamps may appear to violate the principle of
	// causality. In other words, the NTP server's response may indicate
	// that a message was received before it was sent. In such cases, the
	// minimum error may be useful.
	MinError time.Duration

	// KissCode is a 4-character string describing the reason for a
	// "kiss of death" response (stratum = 0). For a list of standard kiss
	// codes, see https://tools.ietf.org/html/rfc5905#section-7.4.
	KissCode string

	// Poll is the maximum interval between successive NTP polling messages.
	// It is not relevant for simple NTP clients like this one.
	Poll time.Duration
}

// Validate checks if the response is valid for the purposes of time
// synchronization.
func (r *Response) Validate() error {
	// Handle invalid stratum values.
	if r.Stratum == 0 {
		return fmt.Errorf("kiss of death received: %s", r.KissCode)
	}
	if r.Stratum >= maxStratum {
		return errors.New("invalid stratum in response")
	}

	// Handle invalid leap second indicator.
	if r.Leap == LeapNotInSync {
		return errors.New("invalid leap second")
	}

	// Estimate the "freshness" of the time. If it exceeds the maximum
	// polling interval (~36 hours), then it cannot be considered "fresh".
	freshness := r.Time.Sub(r.ReferenceTime)
	if freshness > maxPollInterval {
		return errors.New("server clock not fresh")
	}

	// Calculate the peer synchronization distance, lambda:
	//  	lambda := RootDelay/2 + RootDispersion
	// If this value exceeds MAXDISP (16s), then the time is not suitable
	// for synchronization purposes.
	// https://tools.ietf.org/html/rfc5905#appendix-A.5.1.1.
	lambda := r.RootDelay/2 + r.RootDispersion
	if lambda > maxDispersion {
		return errors.New("invalid dispersion")
	}

	// If the server's transmit time is before its reference time, the
	// response is invalid.
	if r.Time.Before(r.ReferenceTime) {
		return errors.New("invalid time reported")
	}

	// nil means the response is valid.
	return nil
}

// Query returns a response from the remote NTP server at address 'host'. The
// response contains the time at which the server responded to the query as
// well as other useful information about the time and the remote server.
func Query(host string) (*Response, error) {
	return QueryWithOptions(host, QueryOptions{})
}

// QueryWithOptions performs the same function as Query but allows for the
// customization of several query options.
func QueryWithOptions(host string, opt QueryOptions) (*Response, error) {
	m, now, err := getTime(host, opt)
	if err != nil {
		return nil, err
	}
	return parseTime(m, now), nil
}

// Time returns the current local time using information returned from the
// remote NTP server at address 'host'. It uses version 4 of the NTP protocol.
// On error, it returns the local system time.
func Time(host string) (time.Time, error) {
	r, err := Query(host)
	if err != nil {
		return time.Now(), err
	}

	err = r.Validate()
	if err != nil {
		return time.Now(), err
	}

	// Use the clock offset to calculate the time.
	return time.Now().Add(r.ClockOffset), nil
}

// getTime performs the NTP server query and returns the response message
// along with the local system time it was received.
func getTime(host string, opt QueryOptions) (*msg, ntpTime, error) {
	if opt.Timeout == 0 {
		opt.Timeout = defaultTimeout
	}
	if opt.Version == 0 {
		opt.Version = defaultNtpVersion
	}
	if opt.Version < 2 || opt.Version > 4 {
		return nil, 0, errors.New("invalid protocol version requested")
	}
	if opt.Port == 0 {
		opt.Port = 123
	}
	if opt.Dial == nil {
		opt.Dial = defaultDial
	}

	// Connect to the remote server.
	con, err := opt.Dial(opt.LocalAddress, 0, host, opt.Port)
	if err != nil {
		return nil, 0, err
	}
	defer con.Close()

	// Set a TTL for the packet if requested.
	if opt.TTL != 0 {
		ipcon := ipv4.NewConn(con)
		err = ipcon.SetTTL(opt.TTL)
		if err != nil {
			return nil, 0, err
		}
	}

	// Set a timeout on the connection.
	con.SetDeadline(time.Now().Add(opt.Timeout))

	// Allocate a message to hold the response.
	recvMsg := new(msg)

	// Allocate a message to hold the query.
	xmitMsg := new(msg)
	xmitMsg.setMode(client)
	xmitMsg.setVersion(opt.Version)
	xmitMsg.setLeap(LeapNotInSync)

	// To ensure privacy and prevent spoofing, try to use a random 64-bit
	// value for the TransmitTime. If crypto/rand couldn't generate a
	// random value, fall back to using the system clock. Keep track of
	// when the messsage was actually transmitted.
	bits := make([]byte, 8)
	_, err = rand.Read(bits)
	var xmitTime time.Time
	if err == nil {
		xmitMsg.TransmitTime = ntpTime(binary.BigEndian.Uint64(bits))
		xmitTime = time.Now()
	} else {
		xmitTime = time.Now()
		xmitMsg.TransmitTime = toNtpTime(xmitTime)
	}

	var buf = &bytes.Buffer{}
	// Transmit the query.
	err = binary.Write(buf, binary.BigEndian, xmitMsg)
	if err != nil {
		return nil, 0, err
	}

	if opt.needAuth {
		if err = writeAuthenMsgToConn(buf, buf.Bytes(), opt.authentication); err != nil {
			return nil, 0, err
		}
	}

	con.Write(buf.Bytes())

	// Receive the response.
	err = binary.Read(con, binary.BigEndian, recvMsg)
	if err != nil {
		return nil, 0, err
	}

	// Keep track of the time the response was received. As of go 1.9,
	// time.Since assumes a monotonic clock, so delta cannot be less than
	// zero.
	delta := time.Since(xmitTime)
	recvTime := toNtpTime(xmitTime.Add(delta))

	// Check for invalid fields.
	if recvMsg.getMode() != server {
		return nil, 0, errors.New("invalid mode in response")
	}
	if recvMsg.TransmitTime == ntpTime(0) {
		return nil, 0, errors.New("invalid transmit time in response")
	}
	if recvMsg.OriginTime != xmitMsg.TransmitTime {
		return nil, 0, errors.New("server response mismatch")
	}
	if recvMsg.ReceiveTime > recvMsg.TransmitTime {
		return nil, 0, errors.New("server clock ticked backwards")
	}

	// Correct the received message's origin time using the actual
	// transmit time.
	recvMsg.OriginTime = toNtpTime(xmitTime)

	return recvMsg, recvTime, nil
}

// defaultDial provides a UDP dialer based on Go's built-in net stack.
func defaultDial(localAddr string, localPort int, remoteAddr string, remotePort int) (net.Conn, error) {
	rhostport := net.JoinHostPort(remoteAddr, strconv.Itoa(remotePort))
	raddr, err := net.ResolveUDPAddr("udp", rhostport)
	if err != nil {
		return nil, err
	}

	var laddr *net.UDPAddr
	if localAddr != "" {
		lhostport := net.JoinHostPort(localAddr, strconv.Itoa(localPort))
		laddr, err = net.ResolveUDPAddr("udp", lhostport)
		if err != nil {
			return nil, err
		}
	}

	return net.DialUDP("udp", laddr, raddr)
}

// parseTime parses the NTP packet along with the packet receive time to
// generate a Response record.
func parseTime(m *msg, recvTime ntpTime) *Response {
	r := &Response{
		Time:           m.TransmitTime.Time(),
		ClockOffset:    offset(m.OriginTime, m.ReceiveTime, m.TransmitTime, recvTime),
		RTT:            rtt(m.OriginTime, m.ReceiveTime, m.TransmitTime, recvTime),
		Precision:      toInterval(m.Precision),
		Stratum:        m.Stratum,
		ReferenceID:    m.ReferenceID,
		ReferenceTime:  m.ReferenceTime.Time(),
		RootDelay:      m.RootDelay.Duration(),
		RootDispersion: m.RootDispersion.Duration(),
		Leap:           m.getLeap(),
		MinError:       minError(m.OriginTime, m.ReceiveTime, m.TransmitTime, recvTime),
		Poll:           toInterval(m.Poll),
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

func rtt(org, rec, xmt, dst ntpTime) time.Duration {
	// round trip delay time
	//   rtt = (dst-org) - (xmt-rec)
	a := dst.Time().Sub(org.Time())
	b := xmt.Time().Sub(rec.Time())
	rtt := a - b
	if rtt < 0 {
		rtt = 0
	}
	return rtt
}

func offset(org, rec, xmt, dst ntpTime) time.Duration {
	// local clock offset
	//   offset = ((rec-org) + (xmt-dst)) / 2
	a := rec.Time().Sub(org.Time())
	b := xmt.Time().Sub(dst.Time())
	return (a + b) / time.Duration(2)
}

func minError(org, rec, xmt, dst ntpTime) time.Duration {
	// Each NTP response contains two pairs of send/receive timestamps.
	// When either pair indicates a "causality violation", we calculate the
	// error as the difference in time between them. The minimum error is
	// the greater of the two causality violations.
	var error0, error1 ntpTime
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

func toInterval(t int8) time.Duration {
	switch {
	case t > 0:
		return time.Duration(uint64(time.Second) << uint(t))
	case t < 0:
		return time.Duration(uint64(time.Second) >> uint(-t))
	default:
		return time.Second
	}
}

func kissCode(id uint32) string {
	isPrintable := func(ch byte) bool { return ch >= 32 && ch <= 126 }

	b := []byte{
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
	return string(b)
}

func writeAuthenMsgToConn(con io.Writer, content []byte, authentication Authentication) error {
	var err error
	// write key id
	if err = binary.Write(con, binary.BigEndian, authentication.KeyID); err != nil {
		return err
	}
	switch {
	case authentication.CryptoMethod&CryptoMd5 == CryptoMd5:
		err = binary.Write(con, binary.BigEndian, getDigestByMd5(content, []byte(authentication.Authentication)))

	case authentication.CryptoMethod&CryptoSha1 == CryptoSha1:
		err = binary.Write(con, binary.BigEndian, getDigestBySha1(content, []byte(authentication.Authentication)))

	case authentication.CryptoMethod&CryptoSha256 == CryptoSha256:
		err = binary.Write(con, binary.BigEndian, getDigestBySha256(content, []byte(authentication.Authentication)))

	case authentication.CryptoMethod&CryptoSha512 == CryptoSha512:
		err = binary.Write(con, binary.BigEndian, getDigestSha512(content, []byte(authentication.Authentication)))

	default:
		return ErrNotSupportCryptoMethod
	}

	return err
}

// get md5 crypto  digest
func getDigestByMd5(content []byte, cryptoBytes []byte) [16]byte {
	data := append(cryptoBytes, content...)
	// 计算哈希值并返回
	hash := md5.Sum(data)
	return hash
}

// get sha1 crypto digest
func getDigestBySha1(content []byte, cryptoBytes []byte) [20]byte {
	data := append(cryptoBytes, content...)
	hash := sha1.Sum(data)
	return hash
}

// get sha256 crypto digest
func getDigestBySha256(content []byte, cryptoBytes []byte) [32]byte {
	data := append(cryptoBytes, content...)
	hash := sha256.Sum256(data)

	return hash
}

// get sha512 crypto digest
func getDigestSha512(content []byte, cryptoBytes []byte) [64]byte {
	data := append(content, cryptoBytes...)
	hash := sha512.Sum512(data)

	return hash
}
