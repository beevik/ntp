// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ntp

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOfflineV5Time32Duration(t *testing.T) {
	cases := []struct {
		Time     time32
		Duration time.Duration
	}{
		{0x00000000, 0},                                         // zero
		{0x10000000, 1 * time.Second},                           // 1 second
		{0x20000000, 2 * time.Second},                           // 2 seconds
		{0x08000000, 500 * time.Millisecond},                    // 0.5 seconds
		{0x04000000, 250 * time.Millisecond},                    // 0.25 seconds
		{0x18000000, 1500 * time.Millisecond},                   // 1.5 seconds
		{0x18000001, 1500*time.Millisecond + 4*time.Nanosecond}, // 1.500000004 seconds
		{0xffffffff, 16*time.Second - 4*time.Nanosecond},        // ~15.999 seconds
	}

	for _, c := range cases {
		d := c.Time.Duration()

		diff := d - c.Duration
		if diff < 0 {
			diff = -diff
		}

		assert.True(t, diff < 2*time.Nanosecond, "Time %#x", c.Time)
	}
}

func TestOfflineV5Time32Roundtrip(t *testing.T) {
	durations := []time.Duration{
		0,
		1 * time.Nanosecond,
		100 * time.Nanosecond,
		1 * time.Microsecond,
		1 * time.Millisecond,
		500 * time.Millisecond,
		1 * time.Second,
		5 * time.Second,
		5*time.Second + 1*time.Nanosecond,
		5*time.Second + 2*time.Nanosecond,
		5*time.Second + 3*time.Nanosecond,
		5*time.Second + 4*time.Nanosecond,
		5*time.Second + 5*time.Nanosecond,
		5*time.Second + 1*time.Millisecond + 1*time.Nanosecond,
		15 * time.Second,
	}

	for _, d := range durations {
		nt := toTime32(d)
		back := nt.Duration()

		diff := back - d
		if diff < 0 {
			diff = -diff
		}

		assert.True(t, diff <= 4*time.Nanosecond, "Time %v", d)
	}
}

func TestOfflineV5Timestamp(t *testing.T) {
	// Era 0 starts at 1900-01-01.
	era0Start := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)

	// Test time at era 0 start.
	ts := timestamp64(0)
	result := ts.Time(0)
	assert.Equal(t, era0Start, result)

	// Test 1 second after era 0 start.
	ts = timestamp64(1 << 32)
	result = ts.Time(0)
	expected := era0Start.Add(1 * time.Second)
	assert.Equal(t, expected, result)

	// Test era 1 (starts at ~2036-02-07).
	ts = timestamp64(0)
	result = ts.Time(1)

	// Era 1 should be 2^32 seconds after era 0.
	era1Start := era0Start.Add(time.Duration(1<<32) * time.Second)
	assert.Equal(t, era1Start, result)
}

func TestOfflineV5TimestampDuration(t *testing.T) {
	cases := []struct {
		Timestamp timestamp64
		Duration  time.Duration
	}{
		{0, 0},
		{1 << 32, 1 * time.Second},
		{1 << 31, 500 * time.Millisecond},
	}

	for _, c := range cases {
		d := c.Timestamp.Duration()
		assert.Equal(t, c.Duration, d, "Time %#x duration=%v", c.Timestamp, d)
	}
}

func TestOfflineV5TimestampRoundtrip(t *testing.T) {
	eraLength := time.Duration((1 << 32) * uint64(time.Second))
	era0Start := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	era1Start := era0Start.Add(eraLength)
	era2Start := era1Start.Add(eraLength)

	cases := []struct {
		Time time.Time
		Era  uint8
	}{
		{era0Start, 0},
		{era0Start.Add(1 * time.Second), 0},
		{era0Start.Add(100 * time.Hour), 0},
		{era0Start.Add(365 * 24 * time.Hour), 0},
		{era0Start.Add(50 * 365 * 24 * time.Hour), 0},
		{era0Start.Add(80 * 365 * 24 * time.Hour), 0},
		{era0Start.Add(120 * 365 * 24 * time.Hour), 0},
		{era0Start.Add(136 * 365 * 24 * time.Hour), 0},
		{era0Start.Add(eraLength - 1*time.Second), 0},
		{era1Start, 1},
		{era1Start.Add(1 * time.Second), 1},
		{era1Start.Add(100 * time.Hour), 1},
		{era1Start.Add(365 * 24 * time.Hour), 1},
		{era1Start.Add(50 * 365 * 24 * time.Hour), 1},
		{era1Start.Add(80 * 365 * 24 * time.Hour), 1},
		{era1Start.Add(120 * 365 * 24 * time.Hour), 1},
		{era1Start.Add(136 * 365 * 24 * time.Hour), 1},
		{era1Start.Add(eraLength - 1*time.Second), 1},
		{era2Start, 2},
		{era2Start.Add(1 * time.Second), 2},
		{era2Start.Add(100 * time.Hour), 2},
		{era2Start.Add(365 * 24 * time.Hour), 2},
		{era2Start.Add(50 * 365 * 24 * time.Hour), 2},
		{era2Start.Add(80 * 365 * 24 * time.Hour), 2},
		{era2Start.Add(120 * 365 * 24 * time.Hour), 2},
		{era2Start.Add(136 * 365 * 24 * time.Hour), 2},
		{era2Start.Add(eraLength - 1*time.Second), 2},
	}

	for _, c := range cases {
		nt := toTimestamp64(c.Time)
		back := nt.Time(c.Era)
		diff := back.Sub(c.Time)
		if diff < 0 {
			diff = -diff
		}
		assert.True(t, diff < 1*time.Nanosecond, "Time '%v', Era %d", c.Time, c.Era)
	}
}

func TestOfflineV5HeaderLayout(t *testing.T) {
	h := &headerV5{}
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

	assert.Equal(t, ntpHeaderSize, buf.Len())
}

func TestOfflineV5HeaderAccessors(t *testing.T) {
	h := &headerV5{}

	h.setVersion(5)
	assert.Equal(t, 5, h.getVersion())

	h.setMode(client)
	assert.Equal(t, client, h.getMode())
	h.setMode(server)
	assert.Equal(t, server, h.getMode())

	h.setLeap(LeapNoWarning)
	assert.Equal(t, LeapNoWarning, h.getLeap())
	h.setLeap(LeapAddSecond)
	assert.Equal(t, LeapIndicator(LeapAddSecond), h.getLeap())

	h.setVersion(5)
	h.setMode(client)
	h.setLeap(LeapNoWarning)
	assert.Equal(t, 5, h.getVersion())
	assert.Equal(t, client, h.getMode())
	assert.Equal(t, LeapNoWarning, h.getLeap())
}

func TestOfflineV5DraftIDExtension(t *testing.T) {
	buf := new(bytes.Buffer)
	writeExtDraftID(buf)

	require.GreaterOrEqual(t, buf.Len(), 4)

	assert.Equal(t, 0, buf.Len()%4, "Extension should be padded to 4-byte boundary")

	data := buf.Bytes()
	xtype := extType(binary.BigEndian.Uint16(data[0:2]))
	xlen := binary.BigEndian.Uint16(data[2:4])

	assert.Equal(t, extDraftID, xtype)
	assert.Equal(t, uint16(buf.Len()), xlen, "Length should include header")

	draftStr := "draft-ietf-ntp-ntpv5-06"
	assert.True(t, bytes.Contains(data[4:], []byte(draftStr)), "Extension should contain draft ID string")
}

func TestOfflineV5BuildRequest(t *testing.T) {
	opt := &QueryOptions{
		Version:   5,
		Timescale: TimescaleUTC,
	}

	clientCookie := uint64(0x1234567890abcdef)
	buf, err := buildV5Request(opt, clientCookie, nil)
	require.NoError(t, err)
	require.NotNil(t, buf)
	require.NotZero(t, clientCookie)

	data := buf.Bytes()
	require.GreaterOrEqual(t, len(data), ntpHeaderSize)

	h, err := parseV5Header(data)
	require.NoError(t, err)
	assert.Equal(t, 5, h.getVersion())
	assert.Equal(t, client, h.getMode())
	assert.Equal(t, clientCookie, h.ClientCookie)
	assert.Equal(t, uint8(TimescaleUTC), h.Timescale)
}

func TestOfflineV5ParseHeader(t *testing.T) {
	h := &headerV5{
		Stratum:      2,
		Poll:         6,
		Precision:    -20,
		RootDelay:    0x10000000, // 1 second in Q4.28
		RootDisp:     0x08000000, // 0.5 seconds in Q4.28
		Timescale:    0,
		Era:          0,
		Flags:        flagSynchronized,
		ServerCookie: 0x1234567890ABCDEF,
		ClientCookie: 0xFEDCBA0987654321,
		ReceiveTime:  1 << 32, // 1 second
		TransmitTime: 2 << 32, // 2 seconds
	}
	h.setVersion(5)
	h.setMode(server)
	h.setLeap(LeapNoWarning)

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

	parsed, err := parseV5Header(buf.Bytes())
	require.NoError(t, err)
	assert.Equal(t, 5, parsed.getVersion())
	assert.Equal(t, server, parsed.getMode())
	assert.Equal(t, LeapNoWarning, parsed.getLeap())
	assert.Equal(t, uint8(2), parsed.Stratum)
	assert.Equal(t, int8(6), parsed.Poll)
	assert.Equal(t, int8(-20), parsed.Precision)
	assert.Equal(t, h.RootDelay, parsed.RootDelay)
	assert.Equal(t, h.RootDisp, parsed.RootDisp)
	assert.Equal(t, h.ServerCookie, parsed.ServerCookie)
	assert.Equal(t, h.ClientCookie, parsed.ClientCookie)
	assert.True(t, parsed.Flags&flagSynchronized != 0)
}

// mockV5Server creates a mock connection that echoes the client cookie.
type mockV5Server struct {
	stratum      uint8
	serverCookie uint64
	request      []byte
	closed       bool
}

func (s *mockV5Server) Read(b []byte) (n int, err error) {
	if len(s.request) < ntpHeaderSize {
		return 0, ErrInvalidTime
	}
	reqHeader, _ := parseV5Header(s.request)

	now := time.Now()
	serverRecv := toTimestamp64(now)
	serverXmit := toTimestamp64(now.Add(1 * time.Millisecond))

	respHeader := &headerV5{
		Stratum:      s.stratum,
		Poll:         6,
		Precision:    -20,
		RootDelay:    toTime32(50 * time.Millisecond),
		RootDisp:     toTime32(10 * time.Millisecond),
		Timescale:    0,
		Era:          0,
		Flags:        flagSynchronized,
		ServerCookie: s.serverCookie,
		ClientCookie: reqHeader.ClientCookie, // Echo the client cookie
		ReceiveTime:  serverRecv,
		TransmitTime: serverXmit,
	}
	respHeader.setVersion(5)
	respHeader.setMode(server)
	respHeader.setLeap(LeapNoWarning)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, respHeader.LiVnMode)
	binary.Write(buf, binary.BigEndian, respHeader.Stratum)
	binary.Write(buf, binary.BigEndian, respHeader.Poll)
	binary.Write(buf, binary.BigEndian, respHeader.Precision)
	binary.Write(buf, binary.BigEndian, respHeader.RootDelay)
	binary.Write(buf, binary.BigEndian, respHeader.RootDisp)
	binary.Write(buf, binary.BigEndian, respHeader.Timescale)
	binary.Write(buf, binary.BigEndian, respHeader.Era)
	binary.Write(buf, binary.BigEndian, respHeader.Flags)
	binary.Write(buf, binary.BigEndian, respHeader.ServerCookie)
	binary.Write(buf, binary.BigEndian, respHeader.ClientCookie)
	binary.Write(buf, binary.BigEndian, respHeader.ReceiveTime)
	binary.Write(buf, binary.BigEndian, respHeader.TransmitTime)

	copy(b, buf.Bytes())
	return buf.Len(), nil
}

func (s *mockV5Server) Write(b []byte) (n int, err error) {
	s.request = make([]byte, len(b))
	copy(s.request, b)
	return len(b), nil
}

func (s *mockV5Server) Close() error {
	s.closed = true
	return nil
}

func (s *mockV5Server) LocalAddr() net.Addr                { return nil }
func (s *mockV5Server) RemoteAddr() net.Addr               { return nil }
func (s *mockV5Server) SetDeadline(t time.Time) error      { return nil }
func (s *mockV5Server) SetReadDeadline(t time.Time) error  { return nil }
func (s *mockV5Server) SetWriteDeadline(t time.Time) error { return nil }

func TestOfflineV5QueryMock(t *testing.T) {
	mockServer := &mockV5Server{
		stratum:      2,
		serverCookie: 0x1234567890ABCDEF,
	}

	opt := &QueryOptions{
		Version:       5,
		Timeout:       5 * time.Second,
		GetSystemTime: time.Now,
	}

	resp, err := queryV5(mockServer, opt)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, 5, resp.Version)
	assert.Equal(t, uint8(2), resp.Stratum)
	assert.Equal(t, LeapNoWarning, resp.Leap)
	assert.True(t, resp.Flags&flagSynchronized != 0)
	assert.False(t, resp.Flags&flagInterleaved != 0)
	assert.Equal(t, TimescaleUTC, resp.Timescale)
	assert.Equal(t, uint8(0), resp.Era)
	assert.Equal(t, uint64(0x1234567890ABCDEF), resp.ServerCookie)
	assert.False(t, mockServer.closed)
}
