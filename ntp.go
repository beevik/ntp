// Copyright 2015 Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ntp provides a simple mechanism for querying the current time from
// a remote NTP server. See RFC 5905. Approach inspired by go-nuts post by
// Michael Hofmann:
//
// https://groups.google.com/forum/?fromgroups#!topic/golang-nuts/FlcdMU5fkLQ
package ntp

import (
	"encoding/binary"
	"errors"
	"net"
	"time"

	"golang.org/x/net/ipv4"
)

type mode uint8

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

const (
	// MaxStratum is the largest allowable NTP stratum value.
	MaxStratum = 16

	nanoPerSec = 1000000000

	defaultNtpVersion = 4

	defaultTimeout  = 5 * time.Second
	maxPollInterval = (1 << 17) * time.Second
	maxDispersion   = 16 * time.Second
)

var (
	ntpEpoch = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
)

// An ntpTime is a 64-bit fixed-point (Q32.32) representation of the number of
// seconds elapsed.
type ntpTime uint64

// Duration interprets the fixed-point ntpTime as a number of elapsed seconds
// and returns the corresponding time.Duration value.
func (t ntpTime) Duration() time.Duration {
	sec := (t >> 32) * nanoPerSec
	frac := (t & 0xffffffff) * nanoPerSec >> 32
	return time.Duration(sec + frac)
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
	frac := (((nsec - sec*nanoPerSec) << 32) + nanoPerSec - 1) / nanoPerSec
	return ntpTime(sec<<32 | frac)
}

// An ntpTimeShort is a 32-bit fixed-point (Q16.16) representation of the
// number of seconds elapsed.
type ntpTimeShort uint32

// Duration interprets the fixed-point ntpTimeShort as a number of elapsed
// seconds and returns the corresponding time.Duration value.
func (t ntpTimeShort) Duration() time.Duration {
	t64 := uint64(t)
	sec := (t64 >> 16) * nanoPerSec
	frac := (t64 & 0xffff) * nanoPerSec >> 16
	return time.Duration(sec + frac)
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

// getLeap returns the leap indicator on the message.
func (m *msg) getLeap() LeapIndicator {
	return LeapIndicator((m.LiVnMode >> 6) & 0x03)
}

// QueryOptions contains the list of configurable options that may be used
// with the QueryWithOptions function.
type QueryOptions struct {
	Timeout      time.Duration // defaults to 5 seconds
	Version      int           // NTP protocol version, defaults to 4
	LocalAddress string        // IP address to use for the client address
	Port         int           // NTP Server port, defaults to 123
	TTL          int           // IP TTL to use for outgoing UDP packets, defaults to system default
}

// A Response contains time data, some of which is returned by the NTP server
// and some of which is calculated by the client.
type Response struct {
	// Time is the transmit time reported by the server.
	Time time.Time

	// RTT is the measured round-trip time estimate between the client and
	// the server.
	RTT time.Duration

	// ClockOffset is the estimated offset of the local clock relative to the
	// server.
	ClockOffset time.Duration

	// Poll is the maximum interval between successive messages.
	Poll time.Duration

	// Precision is the reported precision of the server's clock.
	Precision time.Duration

	// Stratum is the "stratum level" of the server, where 1 is a primary
	// server and 2-15 are secondary servers.
	Stratum uint8

	// ReferenceID is a 32-bit identifier identifying the server or reference
	// clock.
	ReferenceID uint32

	// ReferenceTime is the time when the server's system clock was last set
	// or corrected.
	ReferenceTime time.Time

	// RootDelay is the server's round-trip time to the reference clock.
	RootDelay time.Duration

	// RootDispersion is the server's total dispersion to the reference clock.
	RootDispersion time.Duration

	// Leap is the leap-second indicator.
	Leap LeapIndicator

	// RootDistance is the single-packet estimate of the root synchronization
	// distance. https://tools.ietf.org/html/rfc5905#appendix-A.5.5.2
	RootDistance time.Duration

	// CausalityViolation is an amount of time representing the "causality
	// violation" between the client and the server. It may be used as a
	// lower bound on the current time synchronization error between the
	// client and server clock. A leap second may contribute as much as 1
	// second of causality violation.
	CausalityViolation time.Duration
}

// Validate checks if the response is valid for the purposes of time
// synchronization.
func (r *Response) Validate() error {
	// Check for illegal stratum values.
	if r.Stratum < 0 || r.Stratum > MaxStratum {
		return errors.New("invalid stratum in response")
	}

	// Estimate the "freshness" of the time. If it exceeds the maximum polling
	// interval (~36 hours), then it cannot be considered "fresh".
	freshness := r.Time.Sub(r.ReferenceTime)
	if freshness > maxPollInterval {
		return errors.New("server clock not fresh")
	}

	// Calculate the peer synchronization distance, lambda:
	//  	lambda := RootDelay/2 + RootDispersion
	// If this value exceeds MAXDISP (16s), then the time is not suitable for
	// synchronization purposes.
	// https://tools.ietf.org/html/rfc5905#appendix-A.5.1.1.
	lambda := r.RootDelay/2 + r.RootDispersion
	if lambda > maxDispersion {
		return errors.New("invalid dispersion")
	}

	// If the packet's transmit time is before the server's reference time,
	// it's invalid.
	if r.Time.Before(r.ReferenceTime) {
		return errors.New("invalid time reported")
	}

	// nil means response is valid.
	return nil
}

// Query returns a response from the remote NTP server host. It contains
// the time at which the server transmitted the response as well as other
// useful information about the time and the remote server.
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

// TimeV returns the current time using information from a remote NTP server.
// On error, it returns the local system time. The version may be 2, 3, or 4.
func TimeV(host string, version int) (time.Time, error) {
	m, recvTime, err := getTime(host, QueryOptions{Version: version})
	if err != nil {
		return time.Now(), err
	}

	r := parseTime(m, recvTime)
	err = r.Validate()
	if err != nil {
		return time.Now(), err
	}

	// Use the clock offset to calculate the time.
	return time.Now().Add(r.ClockOffset), nil
}

// Time returns the current time using information from a remote NTP server.
// It uses version 4 of the NTP protocol. On error, it returns the local
// system time.
func Time(host string) (time.Time, error) {
	return TimeV(host, defaultNtpVersion)
}

// getTime performs the NTP server query and returns the response message
// along with the local system time it was received.
func getTime(host string, opt QueryOptions) (*msg, ntpTime, error) {
	if opt.Version == 0 {
		opt.Version = defaultNtpVersion
	}
	if opt.Version < 2 || opt.Version > 4 {
		panic("ntp: invalid version number")
	}

	// Resolve the remote NTP server address.
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, "123"))
	if err != nil {
		return nil, 0, err
	}

	// Resolve the local address if specified as an option.
	var laddr *net.UDPAddr
	if opt.LocalAddress != "" {
		laddr, err = net.ResolveUDPAddr("udp", net.JoinHostPort(opt.LocalAddress, "0"))
		if err != nil {
			return nil, 0, err
		}
	}

	// Override the port if requested.
	if opt.Port != 0 {
		raddr.Port = opt.Port
	}

	// Prepare a "connection" to the remote server.
	con, err := net.DialUDP("udp", laddr, raddr)
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
	if opt.Timeout == 0 {
		opt.Timeout = defaultTimeout
	}
	con.SetDeadline(time.Now().Add(opt.Timeout))

	// Allocate a message to hold the response.
	recvMsg := new(msg)

	// Allocate a message to hold the query.
	xmitMsg := new(msg)
	xmitMsg.setMode(client)
	xmitMsg.setVersion(opt.Version)
	xmitMsg.setLeap(LeapNotInSync)

	// Store the current time in the TransmitTime field. Normally it would
	// be better to use a random value here to ensure privacy and spoofing
	// resistance. But math/rand is not secure, and crypto/rand is not
	// available on every platform.
	xmitMsg.TransmitTime = toNtpTime(time.Now())

	// Transmit the query.
	err = binary.Write(con, binary.BigEndian, xmitMsg)
	if err != nil {
		return nil, 0, err
	}

	// Receive the response.
	err = binary.Read(con, binary.BigEndian, recvMsg)
	if err != nil {
		return nil, 0, err
	}

	// Keep track of the time the response was received.
	recvTime := toNtpTime(time.Now())

	// Check for invalid fields.
	if recvMsg.OriginTime != xmitMsg.TransmitTime {
		return nil, 0, errors.New("server response mismatch")
	}
	if recvMsg.OriginTime > recvTime {
		return nil, 0, errors.New("client clock ticked backwards")
	}
	if recvMsg.ReceiveTime > recvMsg.TransmitTime {
		return nil, 0, errors.New("server clock ticked backwards")
	}

	return recvMsg, recvTime, nil
}

// parseTime parses the NTP packet along with the packet receive time to
// generate a Response record.
func parseTime(m *msg, recvTime ntpTime) *Response {
	r := &Response{
		Time:           m.TransmitTime.Time(),
		RTT:            rtt(m.OriginTime, m.ReceiveTime, m.TransmitTime, recvTime),
		ClockOffset:    offset(m.OriginTime, m.ReceiveTime, m.TransmitTime, recvTime),
		Poll:           toInterval(m.Poll),
		Precision:      toInterval(m.Precision),
		Stratum:        m.Stratum,
		ReferenceID:    m.ReferenceID,
		ReferenceTime:  m.ReferenceTime.Time(),
		RootDelay:      m.RootDelay.Duration(),
		RootDispersion: m.RootDispersion.Duration(),
		Leap:           m.getLeap(),
	}

	// Calculate values depending on other calculated values
	r.RootDistance = rootDistance(r.RTT, r.RootDelay, r.RootDispersion)
	r.CausalityViolation = causalityViolation(r.RTT, r.ClockOffset)

	return r
}

func rtt(t1, t2, t3, t4 ntpTime) time.Duration {
	// round trip delay time (https://tools.ietf.org/html/rfc5905#section-8)
	//   T1 = client send time
	//   T2 = server receive time
	//   T3 = server reply time
	//   T4 = client receive time
	//
	// RTT d:
	//   d = (T4-T1) - (T3-T2)
	a := t4.Time().Sub(t1.Time())
	b := t3.Time().Sub(t2.Time())
	return a - b
}

func offset(t1, t2, t3, t4 ntpTime) time.Duration {
	// local offset equation (https://tools.ietf.org/html/rfc5905#section-8)
	//   T1 = client send time
	//   T2 = server receive time
	//   T3 = server reply time
	//   T4 = client receive time
	//
	// Local clock offset t:
	//   t = ((T2-T1) + (T3-T4)) / 2
	a := t2.Time().Sub(t1.Time())
	b := t3.Time().Sub(t4.Time())
	return (a + b) / time.Duration(2)
}

func rootDistance(rtt, delay, disp time.Duration) time.Duration {
	// RFC5905 suggests more strict check against _peer_ in fit(), that
	// root_dist should be less than MAXDIST + PHI * LOG2D(s.poll).
	// MAXPOLL is 17, so it is approximately at most (1s + 15e-6 * 2**17) =
	// 2.96608 s, but MAXDIST and MAXPOLL are confugurable values in the
	// reference implementation, so only MAXDISP check has hardcoded value
	// in Validate().
	//
	// root_dist should also have following summands
	// + Dispersion towards the peer
	// + jitter of the link to the peer
	// + PHI * (current_uptime - peer->uptime_of_last_update)
	// but all these values are 0 if only single NTP packet was sent.
	if rtt < 0 {
		rtt = 0
	}
	return (rtt+delay)/2 + disp
}

func causalityViolation(rtt, offset time.Duration) time.Duration {
	// NTP query has four timestamps for consecutive events: T1, T2, T3
	// and T4. T1 and T4 use the local clock, T2 and T3 the server clock.
	// RTT    = (T4 - T1) - (T3 - T2)     =   T4 - T3 + T2 - T1
	// Offset = (T2 + T3)/2 - (T4 + T1)/2 = (-T4 + T3 + T2 - T1) / 2
	// => T2 - T1 = RTT/2 + Offset && T4 - T3 = RTT/2 - Offset
	// If system wall-clock is synced to NTP-clock then T2 >= T1 && T4 >= T3.
	// This check may be useful against chrony NTP daemon as it starts
	// relaying sane NTP clock before system wall-clock is actually adjusted.
	violation := rtt / 2
	if offset > 0 {
		violation -= offset
	} else {
		violation += offset
	}

	if violation < 0 {
		return -violation
	}
	return time.Duration(0)
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
