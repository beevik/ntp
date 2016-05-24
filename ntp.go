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
	"fmt"
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

type ntpTime struct {
	Seconds  uint32
	Fraction uint32
}

func (t ntpTime) UTC() time.Time {
	nsec := uint64(t.Seconds)*1e9 + (uint64(t.Fraction) * 1e9 >> 32)
	return time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(nsec))
}

func toNtpTime(t time.Time) ntpTime {
	seconds := uint32(t.Unix() - time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
	fraction := t.Nanosecond() << 32
	return ntpTime{
		Seconds: seconds,
		Fraction: uint32(fraction / 1e9),
	}
}

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
	con.SetDeadline(time.Now().Add(5 * time.Second))

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
	fmt.Println("Got message back", m)

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
func Offset(host string) (int, error) {
	m, err := getTime(host, 4)
	if err != nil {
		return -1, err
	}
	return offset(m.OriginTime.UTC(), m.ReceiveTime.UTC(), m.TransmitTime.UTC(), time.Now())
}

// offset variable names based off the rfc:
// https://tools.ietf.org/html/rfc2030
func offset(t1, t2, t3, t4 time.Time) (int, error) {
	t1n := t1.UnixNano()
	t2n := t2.UnixNano()
	t3n := t3.UnixNano()
	t4n := t4.UnixNano()
	// https://tools.ietf.org/html/rfc2030 page 12
	offset := ((t2n - t1n) + (t3n - t4n)) / 2
	return int(offset), nil
}
