// Copyright 2015 Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ntp provides a simple mechanism for querying the current time
// from a remote NTP server.  This package only supports NTP client mode
// behavior and version 4 of the NTP protocol.  See RFC 5905.
// Approach inspired by go-nuts post by Michael Hofmann:
// https://groups.google.com/forum/?fromgroups#!topic/golang-nuts/FlcdMU5fkLQ
package ntp

import (
	"encoding/binary"
	"net"
	"time"
)

type mode byte

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
	frac float64 = 4294967296.0 // 2^32 as a double
	jan1900to1970 int64 = 2208988800
        maxStratum uint8 = 16
	nanoPerSec    uint64  = 1000000000
)

var (
	timeout = 5 * time.Second
	ntpEpoch = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
)

type ntpTime struct {
	Seconds  uint32
	Fraction uint32
}

func (t ntpTime) UTC() time.Time {
	return time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(t.nsec()))
}

func (t ntpTime) nsec() int64 {
	return int64(t.Seconds)*1e9 + int64(float64(t.Fraction)/frac*1e9)
}

func toNtpTime(t time.Time) ntpTime {
	nsec := uint64(t.UTC().Sub(ntpEpoch))
	seconds := uint32(t.Unix() + jan1900to1970)
	fraction := nsec % nanoPerSec
	return ntpTime{
		Seconds:  seconds,
		Fraction: uint32(fraction << 32 / nanoPerSec),
	}
}

// msg is an internal representation of an NTP packet.
type msg struct {
	LiVnMode       byte // Leap Indicator (2) + Version (3) + Mode (3)
	Stratum        byte
	Poll           byte
	Precision      byte
	RootDelay      uint32
	RootDispersion uint32
	ReferenceId    uint32
	ReferenceTime  ntpTime
	OriginTime     ntpTime
	ReceiveTime    ntpTime
	TransmitTime   ntpTime
}

// Response is a reply returned by Query.
type Response struct {
	Stratum     uint8
	ReceiveTime time.Time
}

// SetVersion sets the NTP protocol version on the message.
func (m *msg) SetVersion(v byte) {
	m.LiVnMode = (m.LiVnMode & 0xc7) | v<<3
}

// SetMode sets the NTP protocol mode on the message.
func (m *msg) SetMode(md mode) {
	m.LiVnMode = (m.LiVnMode & 0xf8) | byte(md)
}

// SetTransmitTime sets the NTP protocol Transmit time
func (m *msg) SetTransmitTime(t time.Time) {
	m.TransmitTime = toNtpTime(t)
}

// Query returns information from the remote NTP server
// specifed as host.  NTP client mode is used.
func Query(host string, version uint8) (*Response, error) {
	m, err := getTime(host, version)
	if err != nil {
		return nil, err
	}
	r := &Response{
		m.Stratum,
		m.ReceiveTime.UTC().Local(),
	}
	// https://tools.ietf.org/html/rfc5905#section-7.3
	if r.Stratum == 0 {
		r.Stratum = maxStratum
	}
	return r, nil
}

// Time returns the "receive time" from the remote NTP server
// specifed as host.  NTP client mode is used.
func getTime(host string, version byte) (*msg, error) {
	if version < 2 || version > 4 {
		panic("ntp: invalid version number")
	}

	raddr, err := net.ResolveUDPAddr("udp", host+":123")
	if err != nil {
		return nil, err
	}

	con, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return nil, err
	}
	defer con.Close()
	con.SetDeadline(time.Now().Add(timeout))

	m := new(msg)
	m.SetMode(client)
	m.SetVersion(version)
	m.SetTransmitTime(time.Now())

	err = binary.Write(con, binary.BigEndian, m)
	if err != nil {
		return nil, err
	}

	err = binary.Read(con, binary.BigEndian, m)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// TimeV returns the "receive time" from the remote NTP server
// specifed as host.  Use the NTP client mode with the requested
// version number (2, 3, or 4).
func TimeV(host string, version byte) (time.Time, error) {
	m, err := getTime(host, version)
	if err != nil {
		return time.Now(), err
	}
	return m.ReceiveTime.UTC().Local(), nil
}

// Time returns the "receive time" from the remote NTP server
// specifed as host.  NTP client mode version 4 is used.
func Time(host string) (time.Time, error) {
	return TimeV(host, 4)
}

// Offset returns the offset in nanoseconds
func Offset(host string) (int64, error) {
	m, err := getTime(host, 4)
	if err != nil {
		return 0, err
	}
	return offset(m.OriginTime, m.ReceiveTime, m.TransmitTime, toNtpTime(time.Now()))
}

// offset variable names based off the rfc:
// https://tools.ietf.org/html/rfc2030
func offset(clientSend, serverReceive, serverTransmit, clientReceive ntpTime) (int64, error) {
	// https://tools.ietf.org/html/rfc2030 page 12
	// d = (T4 - T1) - (T2 - T3)
	// t = ((T2 - T1) + (T3 - T4)) / 2
	i := float64((serverReceive.nsec() - clientSend.nsec()) + (serverTransmit.nsec() - clientReceive.nsec()))
	t := i / 2.0
	return int64(t), nil
}
