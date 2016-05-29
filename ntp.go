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

const maxStratum uint8 = 16

var (
	timeout = 5 * time.Second
)

type ntpTime struct {
	Seconds  uint32
	Fraction uint32
}

func (t ntpTime) UTC() time.Time {
	nsec := uint64(t.Seconds)*1e9 + (uint64(t.Fraction) * 1e9 >> 32)
	return time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(nsec))
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

// Query returns information from the remote NTP server
// specifed as host.  NTP client mode is used.
func Query(host string, version uint8) (*Response, error) {
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

	err = binary.Write(con, binary.BigEndian, m)
	if err != nil {
		return nil, err
	}

	err = binary.Read(con, binary.BigEndian, m)
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

// TimeV returns the "receive time" from the remote NTP server
// specifed as host.  Use the NTP client mode with the requested
// version number (2, 3, or 4).
func TimeV(host string, version byte) (time.Time, error) {
	r, err := Query(host, version)
	if err != nil {
		return time.Now(), err
	}
	return r.ReceiveTime, nil
}

// Time returns the "receive time" from the remote NTP server
// specifed as host.  NTP client mode version 4 is used.
func Time(host string) (time.Time, error) {
	return TimeV(host, 4)
}
