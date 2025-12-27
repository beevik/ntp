// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ntp provides an implementation of a Simple NTP (SNTP) client
// capable of querying the current time from a remote NTP server.  See
// RFC 5905 (https://tools.ietf.org/html/rfc5905) for more details.
//
// This approach grew out of a go-nuts post by Michael Hofmann:
// https://groups.google.com/forum/?fromgroups#!topic/golang-nuts/FlcdMU5fkLQ
package ntp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/ipv4"
)

var (
	ErrAuthFailed              = errors.New("authentication failed")
	ErrAuthNAK                 = errors.New("NTPv5 authentication NAK received")
	ErrInvalidAuthKey          = errors.New("invalid authentication key")
	ErrInvalidDispersion       = errors.New("invalid dispersion in response")
	ErrInvalidDraftID          = errors.New("invalid draft ID value in response")
	ErrInvalidExtensionField   = errors.New("invalid extension field in response")
	ErrInvalidLeapSecond       = errors.New("invalid leap second in response")
	ErrInvalidMode             = errors.New("invalid mode in response")
	ErrInvalidProtocolVersion  = errors.New("invalid protocol version requested")
	ErrInvalidReferenceRequest = errors.New("invalid reference request parameters")
	ErrInvalidStratum          = errors.New("invalid stratum in response")
	ErrInvalidTime             = errors.New("invalid time reported")
	ErrInvalidTransmitTime     = errors.New("invalid transmit time in response")
	ErrKissOfDeath             = errors.New("kiss of death received")
	ErrMACExtensionNotAtEnd    = errors.New("MAC extension not at end of message")
	ErrServerClockFreshness    = errors.New("server clock not fresh")
	ErrServerNotSynchronized   = errors.New("NTPv5 server not synchronized")
	ErrServerResponseMismatch  = errors.New("server response didn't match request")
	ErrServerTickedBackwards   = errors.New("server clock ticked backwards")
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
	defaultNtpPort    = 123
	ntpHeaderSize     = 48
	nanoPerSec        = 1000000000
	maxStratum        = 16
	defaultTimeout    = 5 * time.Second
	maxPollInterval   = (1 << 17) * time.Second
	maxDispersion     = 16 * time.Second
)

// Internal variables
var (
	ntpEra0 = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	ntpEra1 = time.Date(2036, 2, 7, 6, 28, 16, 0, time.UTC)
)

// NTP mode. This package uses only client mode.
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

// An Extension adds custom behaviors capable of modifying NTP packets before
// being sent to the server and processing packets after being received by the
// server.
type Extension interface {
	// ProcessQuery is called when the client is about to send a query to the
	// NTP server. The buffer contains the NTP header. It may also contain
	// extension fields added by extensions processed prior to this one.
	ProcessQuery(buf *bytes.Buffer) error

	// ProcessResponse is called after the client has received the server's
	// NTP response. The buffer contains the entire message returned by the
	// server.
	ProcessResponse(buf []byte) error
}

// The ReferenceIDFilterRequest struct is included in QueryOptions to request
// a chunk of reference ID bloom filter values. Used only for NTPv5 queries.
// See IETF draft-ietf-ntp-ntpv5 section 7.4 for futher details.
type ReferenceIDFilterRequest struct {
	// The octet offset of the reference ID filter chunk to request. Must be
	// less than or equal to 512.
	ChunkOffset uint16

	// The number of octets in the requested reference ID filter chunk. The
	// sum of ChunkOffset and ChunkSize must be less than or equal to 512.
	ChunkSize uint16
}

// QueryOptions contains configurable options used by the QueryWithOptions
// function.
type QueryOptions struct {
	// Timeout determines how long the client waits for a response from the
	// server before failing with a timeout error. Defaults to 5 seconds.
	Timeout time.Duration

	// Version of the NTP protocol to use. Defaults to 4. Allowed values
	// include 3, 4, and 5. The IETF has not finalized version 5 of the NTP
	// protocol, so version 5 support is considered experimental and should
	// not be used in production.
	Version int

	// LocalAddress contains the local IP address to use when creating a
	// connection to the remote NTP server. This may be useful when the local
	// system has more than one IP address. This address should not contain
	// a port number.
	LocalAddress string

	// TTL specifies the maximum number of IP hops before the query datagram
	// is dropped by the network. Defaults to the local system's default value.
	TTL int

	// Timescale requests a specific timescale (UTC, TAI, UT1, etc.) from an
	// NTPv5 server. Used only by NTPv5 servers. Most servers support only UTC
	// (default).
	Timescale Timescale

	// Auth contains the settings used to configure NTP symmetric key
	// authentication. See RFC 5905 for further details.
	Auth AuthOptions

	// Extensions may be added to modify NTP queries before they are
	// transmitted and to process NTP responses after they arrive.
	Extensions []Extension

	// GetSystemTime is a callback used to override the default method of
	// obtaining the local system time during time synchronization. If not
	// specified, time.Now is used.
	GetSystemTime func() time.Time

	// RequestReferenceIDFilter is an optional field used to request NTPv5
	// reference ID bloom filter values. The filter values are returned in the
	// Response struct's ReferenceIDFilterValues field. Only used with NTPv5
	// queries.
	RequestReferenceIDFilter ReferenceIDFilterRequest

	// RequestServerInfo indicates whether to request server information
	// from an NTPv5 server. If true, the client requests that the server
	// include the NTP versions it supports.
	RequestServerInfo bool

	// Dialer is a callback used to override the default UDP network dialer.
	// The localAddress is directly copied from the LocalAddress field
	// specified in QueryOptions. It may be the empty string or a host address
	// (without port number). The remoteAddress is the "host:port" string
	// derived from the first parameter to QueryWithOptions.  The
	// remoteAddress is guaranteed to include a port number.
	Dialer func(localAddress, remoteAddress string) (net.Conn, error)

	// Dial is a callback used to override the default UDP network dialer.
	//
	// DEPRECATED. Use Dialer instead.
	Dial func(laddr string, lport int, raddr string, rport int) (net.Conn, error)

	// Port indicates the port used to reach the remote NTP server.
	//
	// DEPRECATED. Embed the port number in the query address string instead.
	Port int
}

// A Response contains time data, some of which is returned by the NTP server
// and some of which is calculated by this client.
type Response struct {
	// ClockOffset is the estimated offset of the local system clock relative
	// to the server's clock. Add this value to subsequent local system clock
	// times in order to obtain a time that is synchronized to the server's
	// clock.
	ClockOffset time.Duration

	// Time is the time the server transmitted this response, measured using
	// its own clock. You should not use this value for time synchronization
	// purposes. Add ClockOffset to your system clock instead.
	Time time.Time

	// RTT is the measured round-trip-time delay estimate between the client
	// and the server.
	RTT time.Duration

	// Precision is the reported precision of the server's clock.
	Precision time.Duration

	// Version is the NTP protocol version number reported by the server.
	// Supported values include 3, 4, and 5.
	Version int

	// Stratum is the "stratum level" of the server. The smaller the number,
	// the closer the server is to the reference clock. Stratum 1 servers are
	// attached directly to the reference clock. For NTPv3 and NTPv4, a
	// stratum value of 0 indicates the "kiss of death," which typically
	// occurs when the client issues too many requests to the server in a
	// short period of time.
	Stratum uint8

	// ReferenceID is a 32-bit integer used to help identify which server or
	// reference clock generated the reported time. For stratum 1 servers,
	// this is typically a meaningful zero-padded ASCII-encoded string
	// assigned to the clock. For stratum 2+ servers, this is a reference
	// identifier for the server and is either the server's IPv4 address or a
	// hash of its IPv6 address. For kiss-of-death responses (stratum 0), this
	// is the ASCII-encoded "kiss code". Used only by NTPv3 and NTPv4 servers.
	ReferenceID uint32

	// ReferenceIDFilterValues contains the requested chunk of reference ID
	// bloom filter values. The size and offset of this chunk are determined
	// by the RequestReferenceIDFilter field in QueryOptions. Used only in
	// NTPv5.
	ReferenceIDFilterValues []byte

	// ReferenceTime is the time the server last updated its local clock.
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

	// KissCode is a 4-character string describing the reason for a "kiss of
	// death" response (stratum=0). Not used by NTPv5. For a list of standard
	// kiss codes, see https://tools.ietf.org/html/rfc5905#section-7.4.
	KissCode string

	// Poll is the maximum interval between successive NTP query messages to
	// the server.
	Poll time.Duration

	// Timescale indicates the time reference system used by the server. Only
	// set for NTPv5 responses.
	Timescale Timescale

	// Era is the NTP era number. Era 0 spans 1900-2036, Era 1 spans
	// 2036-2172, etc. Only set for NTPv5 responses.
	Era uint8

	// Flags reported by the server.
	Flags ResponseFlags

	// ServerCookie is the session cookie returned by an NTPv5 server. Only
	// set for NTPv5 responses.
	ServerCookie uint64

	authErr error
}

type ResponseFlags uint32

const (
	// FlagSynchronized indicates whether the server is currently synchronized
	// to a reference clock. Only reported by NTPv5 servers. For NTPv3 and NTPv4
	// servers, the response always has this flag set.
	FlagSynchronized ResponseFlags = 1 << iota

	// FlagInterleaved indicates whether the NTPv5 response is interleaved
	// mode. Only reported by NTPv5 servers. For NTPv3 and NTPv4 servers,
	// the response never has this flag set.
	FlagInterleaved
)

// IsKissOfDeath returns true if the response is a "kiss of death" from the
// remote server. If this function returns true, you may examine the
// response's KissCode value to determine the reason for the kiss of death.
func (r *Response) IsKissOfDeath() bool {
	return r.Version < 5 && r.Stratum == 0
}

// ReferenceString returns the response's ReferenceID value formatted as a
// string. If the response's stratum is zero, then the "kiss o' death" string
// is returned. If stratum is one, then the server is a reference clock and
// the reference clock's name is returned. If stratum is two or greater, then
// the ID is either an IPv4 address or an MD5 hash of the IPv6 address; in
// either case the reference string is reported as 4 dot-separated
// decimal-based integers.
func (r *Response) ReferenceString() string {
	if r.Version == 5 {
		return ""
	}

	if r.Stratum == 0 {
		return kissCode(r.ReferenceID)
	}

	var b [4]byte
	binary.BigEndian.PutUint32(b[:], r.ReferenceID)

	if r.Stratum == 1 {
		const dot = rune(0x22c5)
		var r []rune
		for i := range b {
			if b[i] == 0 {
				break
			}
			if b[i] >= 32 && b[i] <= 126 {
				r = append(r, rune(b[i]))
			} else {
				r = append(r, dot)
			}
		}
		return fmt.Sprintf(".%s.", string(r))
	}

	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

// Validate checks if the response is valid for the purposes of time
// synchronization.
func (r *Response) Validate() error {
	// Forward authentication errors.
	if r.authErr != nil {
		return r.authErr
	}

	// Handle invalid stratum values.
	if r.Stratum == 0 {
		return ErrKissOfDeath
	}
	if r.Stratum >= maxStratum {
		return ErrInvalidStratum
	}

	// Estimate the "freshness" of the time. If it exceeds the maximum
	// polling interval (~36 hours), then it cannot be considered "fresh".
	freshness := r.Time.Sub(r.ReferenceTime)
	if freshness > maxPollInterval {
		return ErrServerClockFreshness
	}

	// Calculate the peer synchronization distance, lambda:
	//  	lambda := RootDelay/2 + RootDispersion
	// If this value exceeds MAXDISP (16s), then the time is not suitable
	// for synchronization purposes.
	// https://tools.ietf.org/html/rfc5905#appendix-A.5.1.1.
	lambda := r.RootDelay/2 + r.RootDispersion
	if lambda > maxDispersion {
		return ErrInvalidDispersion
	}

	// If the server's transmit time is before its reference time, the
	// response is invalid.
	if r.Time.Before(r.ReferenceTime) {
		return ErrInvalidTime
	}

	// Handle invalid leap second indicator.
	if r.Leap == LeapNotInSync {
		return ErrInvalidLeapSecond
	}

	// For NTPv5, ensure the server is synchronized.
	if (r.Flags & FlagSynchronized) == 0 {
		return ErrServerNotSynchronized
	}

	// nil means the response is valid.
	return nil
}

// Query requests time data from a remote NTP server. The response contains
// information from which a more accurate local time can be inferred.
//
// The server address is of the form "host", "host:port", "host%zone:port",
// "[host]:port" or "[host%zone]:port". The host may contain an IPv4, IPv6 or
// domain name address. When specifying both a port and an IPv6 address, one
// of the bracket formats must be used. If no port is included, NTP default
// port 123 is used.
func Query(address string) (*Response, error) {
	return QueryWithOptions(address, QueryOptions{})
}

// QueryWithOptions performs the same function as Query but allows for the
// customization of certain query behaviors. See the comments for Query and
// QueryOptions for further details.
func QueryWithOptions(remoteAddress string, opt QueryOptions) (*Response, error) {
	if opt.Version == 0 {
		opt.Version = defaultNtpVersion
	}
	if opt.Version < 2 || opt.Version > 5 {
		return nil, ErrInvalidProtocolVersion
	}

	if opt.Timeout == 0 {
		opt.Timeout = defaultTimeout
	}
	if opt.Port == 0 {
		opt.Port = defaultNtpPort
	}
	if opt.GetSystemTime == nil {
		opt.GetSystemTime = time.Now
	}
	if opt.Dial != nil {
		// wrapper for the deprecated Dial callback.
		opt.Dialer = func(la, ra string) (net.Conn, error) {
			return dialWrapper(la, ra, opt.Dial)
		}
	}
	if opt.Dialer == nil {
		opt.Dialer = defaultDialer
	}

	// Compose a conforming host:port remote address string, adding the port
	// number if necessary.
	remoteAddress, err := fixHostPort(remoteAddress, opt.Port)
	if err != nil {
		return nil, err
	}

	// Connect to the NTP server.
	conn, err := opt.Dialer(opt.LocalAddress, remoteAddress)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Set a TTL for the packet if requested.
	if opt.TTL != 0 {
		ipcon := ipv4.NewConn(conn)
		err = ipcon.SetTTL(opt.TTL)
		if err != nil {
			return nil, err
		}
	}

	// Set a timeout on the connection.
	conn.SetDeadline(time.Now().Add(opt.Timeout))

	// Perform the version-specific query.
	if opt.Version == 5 {
		return queryV5(conn, &opt)
	} else {
		return queryV4(conn, &opt)
	}
}

// Time returns the current, corrected local time using information returned
// from the remote NTP server. On error, Time returns the uncorrected local
// system time. This function can only be used with NTPv3 and NTPv4 servers.
//
// The server address is of the form "host", "host:port", "host%zone:port",
// "[host]:port" or "[host%zone]:port". The host may contain an IPv4, IPv6 or
// domain name address. When specifying both a port and an IPv6 address, one
// of the bracket formats must be used. If no port is included, NTP default
// port 123 is used.
func Time(address string) (time.Time, error) {
	r, err := Query(address)
	if err != nil {
		return time.Now(), err
	}

	err = r.Validate()
	if err != nil {
		return time.Now(), err
	}

	// Use the response's clock offset to calculate an accurate time.
	return time.Now().Add(r.ClockOffset), nil
}

// dialWrapper is used to wrap the deprecated Dial callback in QueryOptions.
func dialWrapper(la, ra string,
	dial func(la string, lp int, ra string, rp int) (net.Conn, error)) (net.Conn, error) {
	rhost, rport, err := net.SplitHostPort(ra)
	if err != nil {
		return nil, err
	}

	rportValue, err := strconv.Atoi(rport)
	if err != nil {
		return nil, err
	}

	return dial(la, 0, rhost, rportValue)
}

// defaultDialer provides a UDP dialer based on Go's built-in net stack.
func defaultDialer(localAddress, remoteAddress string) (net.Conn, error) {
	var laddr *net.UDPAddr
	if localAddress != "" {
		var err error
		laddr, err = net.ResolveUDPAddr("udp", net.JoinHostPort(localAddress, "0"))
		if err != nil {
			return nil, err
		}
	}

	raddr, err := net.ResolveUDPAddr("udp", remoteAddress)
	if err != nil {
		return nil, err
	}

	return net.DialUDP("udp", laddr, raddr)
}

// fixHostPort examines an address in one of the accepted forms and modifies
// it to include a port number if necessary.
func fixHostPort(address string, defaultPort int) (fixed string, err error) {
	if len(address) == 0 {
		return "", errors.New("address string is empty")
	}

	// If the address is wrapped in brackets, append a port if necessary.
	if address[0] == '[' {
		end := strings.IndexByte(address, ']')
		switch {
		case end < 0:
			return "", errors.New("missing ']' in address")
		case end+1 == len(address):
			return fmt.Sprintf("%s:%d", address, defaultPort), nil
		case address[end+1] == ':':
			return address, nil
		default:
			return "", errors.New("unexpected character following ']' in address")
		}
	}

	// No colons? Must be a port-less IPv4 or domain address.
	last := strings.LastIndexByte(address, ':')
	if last < 0 {
		return fmt.Sprintf("%s:%d", address, defaultPort), nil
	}

	// Exactly one colon? A port have been included along with an IPv4 or
	// domain address. (IPv6 addresses are guaranteed to have more than one
	// colon.)
	prev := strings.LastIndexByte(address[:last], ':')
	if prev < 0 {
		return address, nil
	}

	// Two or more colons means we must have an IPv6 address without a port.
	return fmt.Sprintf("[%s]:%d", address, defaultPort), nil
}

// toInterval converts an NTP poll interval exponent into a time.Duration.
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
