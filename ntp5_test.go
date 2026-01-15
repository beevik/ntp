// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ntp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func logResponseV5(t *testing.T, r *Response) {
	now := time.Now()
	t.Logf("[%s] ClockOffset: %s", host, r.ClockOffset)
	t.Logf("[%s]  SystemTime: %s", host, fmtTime(now))
	t.Logf("[%s]   ~TrueTime: %s", host, fmtTime(now.Add(r.ClockOffset)))
	t.Logf("[%s]    XmitTime: %s", host, fmtTime(r.Time))
	t.Logf("[%s]     Version: %d", host, r.Version)
	t.Logf("[%s]     Stratum: %d", host, r.Stratum)
	t.Logf("[%s]        Leap: %s", host, fmtLeapIndicator(r.Leap))
	t.Logf("[%s]       Flags: %s", host, fmtResponseFlags(r.Flags))
	t.Logf("[%s]         Era: %d", host, r.Era)
	t.Logf("[%s]   Timescale: %s", host, fmtTimescale(r.Timescale))
	t.Logf("[%s]     Offsets: %s", host, fmtTimescaleOffsets(r.TimescaleOffsets))
	t.Logf("[%s]  RefIDBytes: %s", host, fmtRefIDFilter(r.ReferenceIDFilterValues))
	t.Logf("[%s]     RefTime: %s", host, fmtTime(r.ReferenceTime))
	t.Logf("[%s]  MonoOffset: %s", host, r.MonotonicOffset)
	t.Logf("[%s]   MonoEpoch: %s", host, fmtEpoch(r.MonotonicEpochID))
	t.Logf("[%s]   Supported: %v", host, r.SupportedVersions)
	t.Logf("[%s]         RTT: %s", host, r.RTT)
	t.Logf("[%s]        Poll: %s", host, r.Poll)
	t.Logf("[%s]  CorrDelay0: %s", host, r.Correction.OriginDelay)
	t.Logf("[%s]   CorrPath0: 0x%08x", host, r.Correction.OriginPathID)
	t.Logf("[%s]  CorrDelay1: %s", host, r.Correction.ReturnDelay)
	t.Logf("[%s]   CorrPath1: 0x%08x", host, r.Correction.ReturnPathID)
	t.Logf("[%s]   Precision: %s", host, r.Precision)
	t.Logf("[%s]   RootDelay: %s", host, r.RootDelay)
	t.Logf("[%s]    RootDisp: %s", host, r.RootDispersion)
	t.Logf("[%s]    RootDist: %s", host, r.RootDistance)
	t.Logf("[%s]    MinError: %s", host, r.MinError)
	t.Logf("[%s]   SrvCookie: %s", host, fmtCookie(r.ServerCookie))
}

func fmtRefIDFilter(filter []byte) string {
	if filter == nil {
		return "<nil>"
	}
	l := min(len(filter), 24)
	return "0x" + hex.EncodeToString(filter[:l]) + "..."
}

func fmtEpoch(epoch uint32) string {
	if epoch == 0 {
		return "<zero>"
	}
	return fmt.Sprintf("0x%08x", epoch)
}

func fmtTimescale(ts Timescale) string {
	switch ts {
	case TimescaleUTC:
		return "UTC"
	case TimescaleTAI:
		return "TAI"
	case TimescaleUT1:
		return "UT1"
	case TimescaleUTCSmeared:
		return "UTC(smeared)"
	default:
		return "Unknown"
	}
}

func fmtTimescaleOffset(o TimescaleOffset) string {
	return fmt.Sprintf("%s=%v", fmtTimescale(o.Timescale), o.Offset)
}

func fmtTimescaleOffsets(offsets []TimescaleOffset) string {
	if offsets == nil {
		return "<none>"
	}

	var s strings.Builder
	s.WriteString("[")
	for i, o := range offsets {
		if i > 0 {
			s.WriteString(", ")
		}
		s.WriteString(fmtTimescaleOffset(o))
	}
	s.WriteString("]")

	return s.String()
}

func fmtCookie(c uint64) string {
	if c == 0 {
		return "<zero>"
	}
	return fmt.Sprintf("0x%016x", c)
}

func TestOnlineV5Query(t *testing.T) {
	if host == "localhost" {
		t.Skip("Timeout test not available with localhost NTP server.")
		return
	}

	opt := QueryOptions{
		Version: 5,
		ReferenceIDRequest: ReferenceIDRequest{
			ChunkOffset: 0,
			ChunkSize:   uint16(512),
		},
		Timescale:                TimescaleUTC,
		AdditionalTimescales:     []Timescale{TimescaleTAI, TimescaleUT1, TimescaleUTCSmeared},
		RequestSupportedVersions: true,
		RequestCorrection:        true,
		RequestReferenceTime:     true,
		RequestMonotonic:         true,
		RequestInterleavedMode:   true,
	}

	// Force an immediate timeout.
	r, err := QueryWithOptions(host, opt)
	if isError(t, host, err) {
		return
	}
	assertValid(t, r)
	logResponseV5(t, r)
}

func TestOfflineV5Time32Duration(t *testing.T) {
	cases := []struct {
		Time     timeShortV5
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

func TestOfflineV5TimeShortRoundtrip(t *testing.T) {
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
		nt := toTimeShortV5(d)
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
	ts := timestamp(0)
	result := ts.Time(0)
	assert.Equal(t, era0Start, result)

	// Test 1 second after era 0 start.
	ts = timestamp(1 << 32)
	result = ts.Time(0)
	expected := era0Start.Add(1 * time.Second)
	assert.Equal(t, expected, result)

	// Test era 1 (starts at ~2036-02-07).
	ts = timestamp(0)
	result = ts.Time(1)

	// Era 1 should be 2^32 seconds after era 0.
	era1Start := era0Start.Add(time.Duration(1<<32) * time.Second)
	assert.Equal(t, era1Start, result)
}

func TestOfflineV5TimestampDuration(t *testing.T) {
	cases := []struct {
		Timestamp timestamp
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
	era0Start := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
	era1Start := era0Start.Add(ntpEraLength)
	era2Start := era1Start.Add(ntpEraLength)

	cases := []struct {
		Time time.Time
		Era  uint8
	}{
		{era0Start, 0},
		{era0Start.Add(1 * time.Nanosecond), 0},
		{era0Start.Add(2 * time.Nanosecond), 0},
		{era0Start.Add(3 * time.Nanosecond), 0},
		{era0Start.Add(4 * time.Nanosecond), 0},
		{era0Start.Add(1 * time.Microsecond), 0},
		{era0Start.Add(1 * time.Millisecond), 0},
		{era0Start.Add(1*time.Millisecond + 1*time.Microsecond), 0},
		{era0Start.Add(1*time.Millisecond + 1*time.Microsecond + 1*time.Nanosecond), 0},
		{era0Start.Add(1 * time.Second), 0},
		{era0Start.Add(100 * time.Hour), 0},
		{era0Start.Add(365 * 24 * time.Hour), 0},
		{era0Start.Add(36 * 365 * 24 * time.Hour), 0},
		{era0Start.Add(72 * 365 * 24 * time.Hour), 0},
		{era0Start.Add(108 * 365 * 24 * time.Hour), 0},
		{era0Start.Add(136 * 365 * 24 * time.Hour), 0},
		{era0Start.Add(ntpEraLength - 1*time.Second), 0},
		{era1Start, 1},
		{era1Start.Add(1 * time.Second), 1},
		{era1Start.Add(100 * time.Hour), 1},
		{era1Start.Add(365 * 24 * time.Hour), 1},
		{era1Start.Add(36 * 365 * 24 * time.Hour), 1},
		{era1Start.Add(72 * 365 * 24 * time.Hour), 1},
		{era1Start.Add(108 * 365 * 24 * time.Hour), 1},
		{era1Start.Add(136 * 365 * 24 * time.Hour), 1},
		{era1Start.Add(ntpEraLength - 1*time.Second), 1},
		{era2Start, 2},
		{era2Start.Add(1 * time.Second), 2},
		{era2Start.Add(100 * time.Hour), 2},
		{era2Start.Add(365 * 24 * time.Hour), 2},
		{era2Start.Add(36 * 365 * 24 * time.Hour), 2},
		{era2Start.Add(72 * 365 * 24 * time.Hour), 2},
		{era2Start.Add(108 * 365 * 24 * time.Hour), 2},
		{era2Start.Add(136 * 365 * 24 * time.Hour), 2},
		{era2Start.Add(ntpEraLength - 1*time.Second), 2},
	}

	for _, c := range cases {
		nt := toTimestamp(c.Time)
		back := nt.Time(c.Era)
		diff := back.Sub(c.Time)
		if diff < 0 {
			diff = -diff
		}
		assert.True(t, diff < 1*time.Nanosecond, "Time '%v', Era %d", c.Time, c.Era)
	}
}

func TestOfflineV5MsgLayout(t *testing.T) {
	m := &messageV5{}
	buf := new(bytes.Buffer)

	binary.Write(buf, binary.BigEndian, m.LiVnMode)
	binary.Write(buf, binary.BigEndian, m.Stratum)
	binary.Write(buf, binary.BigEndian, m.Poll)
	binary.Write(buf, binary.BigEndian, m.Precision)
	binary.Write(buf, binary.BigEndian, m.RootDelay)
	binary.Write(buf, binary.BigEndian, m.RootDisp)
	binary.Write(buf, binary.BigEndian, m.Timescale)
	binary.Write(buf, binary.BigEndian, m.Era)
	binary.Write(buf, binary.BigEndian, m.Flags)
	binary.Write(buf, binary.BigEndian, m.ServerCookie)
	binary.Write(buf, binary.BigEndian, m.ClientCookie)
	binary.Write(buf, binary.BigEndian, m.ReceiveTime)
	binary.Write(buf, binary.BigEndian, m.TransmitTime)

	assert.Equal(t, msgSize, buf.Len())
}

func TestOfflineV5MsgAccessors(t *testing.T) {
	m := &messageV5{}

	m.setVersion(5)
	assert.Equal(t, 5, m.getVersion())

	m.setMode(requestMode)
	assert.Equal(t, requestMode, m.getMode())
	m.setMode(responseMode)
	assert.Equal(t, responseMode, m.getMode())

	m.setLeap(LeapNoWarning)
	assert.Equal(t, LeapNoWarning, m.getLeap())
	m.setLeap(LeapAddSecond)
	assert.Equal(t, LeapIndicator(LeapAddSecond), m.getLeap())

	m.setVersion(5)
	m.setMode(requestMode)
	m.setLeap(LeapNoWarning)
	assert.Equal(t, 5, m.getVersion())
	assert.Equal(t, requestMode, m.getMode())
	assert.Equal(t, LeapNoWarning, m.getLeap())
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
	assert.Equal(t, buf.Len(), paddedLen(int(xlen)), "Length should include header")

	assert.True(t, bytes.Contains(data[4:], []byte(draftID)), "Extension should contain draft ID string")
}

func TestOfflineV5BuildRequest(t *testing.T) {
	opt := &QueryOptions{
		Version:   5,
		Timescale: TimescaleUTC,
	}

	clientCookie := uint64(0x1234567890abcdef)
	buf, err := buildV5Request(opt, clientCookie)
	require.NoError(t, err)
	require.NotNil(t, buf)
	require.NotZero(t, clientCookie)

	data := buf.Bytes()
	require.GreaterOrEqual(t, len(data), msgSize)

	m, err := parseV5Response(data)
	require.NoError(t, err)
	assert.Equal(t, 5, m.getVersion())
	assert.Equal(t, requestMode, m.getMode())
	assert.Equal(t, clientCookie, m.ClientCookie)
	assert.Equal(t, uint8(TimescaleUTC), m.Timescale)
}

func TestOfflineV5ParseMsg(t *testing.T) {
	m := &messageV5{
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
	m.setVersion(5)
	m.setMode(requestMode)
	m.setLeap(LeapNoWarning)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, m.LiVnMode)
	binary.Write(buf, binary.BigEndian, m.Stratum)
	binary.Write(buf, binary.BigEndian, m.Poll)
	binary.Write(buf, binary.BigEndian, m.Precision)
	binary.Write(buf, binary.BigEndian, m.RootDelay)
	binary.Write(buf, binary.BigEndian, m.RootDisp)
	binary.Write(buf, binary.BigEndian, m.Timescale)
	binary.Write(buf, binary.BigEndian, m.Era)
	binary.Write(buf, binary.BigEndian, m.Flags)
	binary.Write(buf, binary.BigEndian, m.ServerCookie)
	binary.Write(buf, binary.BigEndian, m.ClientCookie)
	binary.Write(buf, binary.BigEndian, m.ReceiveTime)
	binary.Write(buf, binary.BigEndian, m.TransmitTime)

	parsed, err := parseV5Response(buf.Bytes())
	require.NoError(t, err)
	assert.Equal(t, 5, parsed.getVersion())
	assert.Equal(t, requestMode, parsed.getMode())
	assert.Equal(t, LeapNoWarning, parsed.getLeap())
	assert.Equal(t, uint8(2), parsed.Stratum)
	assert.Equal(t, int8(6), parsed.Poll)
	assert.Equal(t, int8(-20), parsed.Precision)
	assert.Equal(t, m.RootDelay, parsed.RootDelay)
	assert.Equal(t, m.RootDisp, parsed.RootDisp)
	assert.Equal(t, m.ServerCookie, parsed.ServerCookie)
	assert.Equal(t, m.ClientCookie, parsed.ClientCookie)
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
	if len(s.request) < msgSize {
		return 0, ErrInvalidTime
	}
	requestMsg, _ := parseV5Response(s.request)

	now := time.Now()
	serverRecv := toTimestamp(now)
	serverXmit := toTimestamp(now.Add(1 * time.Millisecond))

	responseMsg := &messageV5{
		Stratum:      s.stratum,
		Poll:         6,
		Precision:    -20,
		RootDelay:    toTimeShortV5(50 * time.Millisecond),
		RootDisp:     toTimeShortV5(10 * time.Millisecond),
		Timescale:    0,
		Era:          0,
		Flags:        flagSynchronized,
		ServerCookie: s.serverCookie,
		ClientCookie: requestMsg.ClientCookie, // Echo the client cookie
		ReceiveTime:  serverRecv,
		TransmitTime: serverXmit,
	}
	responseMsg.setVersion(5)
	responseMsg.setMode(responseMode)
	responseMsg.setLeap(LeapNoWarning)

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, responseMsg.LiVnMode)
	binary.Write(buf, binary.BigEndian, responseMsg.Stratum)
	binary.Write(buf, binary.BigEndian, responseMsg.Poll)
	binary.Write(buf, binary.BigEndian, responseMsg.Precision)
	binary.Write(buf, binary.BigEndian, responseMsg.RootDelay)
	binary.Write(buf, binary.BigEndian, responseMsg.RootDisp)
	binary.Write(buf, binary.BigEndian, responseMsg.Timescale)
	binary.Write(buf, binary.BigEndian, responseMsg.Era)
	binary.Write(buf, binary.BigEndian, responseMsg.Flags)
	binary.Write(buf, binary.BigEndian, responseMsg.ServerCookie)
	binary.Write(buf, binary.BigEndian, responseMsg.ClientCookie)
	binary.Write(buf, binary.BigEndian, responseMsg.ReceiveTime)
	binary.Write(buf, binary.BigEndian, responseMsg.TransmitTime)

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
