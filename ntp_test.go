// Copyright 2015-2023 Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ntp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	host       = "0.beevik-ntp.pool.ntp.org"
	refID      = 0xc0a80001
	timeFormat = "Mon Jan _2 2006  15:04:05.00000000 (MST)"
)

func isNil(t *testing.T, host string, err error) bool {
	switch {
	case err == nil:
		return true
	case err == ErrKissOfDeath:
		// log instead of error, so test isn't failed
		t.Logf("[%s] Query kiss of death (ignored)", host)
		return false
	case strings.Contains(err.Error(), "timeout"):
		// log instead of error, so test isn't failed
		t.Logf("[%s] Query timeout (ignored): %s", host, err)
		return false
	default:
		// error, so test fails
		t.Errorf("[%s] Query failed: %s", host, err)
		return false
	}
}

func assertValid(t *testing.T, r *Response) {
	err := r.Validate()
	_ = isNil(t, host, err)
}

func assertInvalid(t *testing.T, r *Response) {
	err := r.Validate()
	if err == nil {
		t.Errorf("[%s] Response unexpectedly valid\n", host)
	}
}

func logResponse(t *testing.T, r *Response) {
	now := time.Now()
	t.Logf("[%s] ClockOffset: %s", host, r.ClockOffset)
	t.Logf("[%s]  SystemTime: %s", host, now.Format(timeFormat))
	t.Logf("[%s]   ~TrueTime: %s", host, now.Add(r.ClockOffset).Format(timeFormat))
	t.Logf("[%s]    XmitTime: %s", host, r.Time.Format(timeFormat))
	t.Logf("[%s]     Stratum: %d", host, r.Stratum)
	t.Logf("[%s]       RefID: %s (0x%08x)", host, formatRefID(r.ReferenceID, r.Stratum), r.ReferenceID)
	t.Logf("[%s]     RefTime: %s", host, r.ReferenceTime.Format(timeFormat))
	t.Logf("[%s]         RTT: %s", host, r.RTT)
	t.Logf("[%s]        Poll: %s", host, r.Poll)
	t.Logf("[%s]   Precision: %s", host, r.Precision)
	t.Logf("[%s]   RootDelay: %s", host, r.RootDelay)
	t.Logf("[%s]    RootDisp: %s", host, r.RootDispersion)
	t.Logf("[%s]    RootDist: %s", host, r.RootDistance)
	t.Logf("[%s]    MinError: %s", host, r.MinError)
	t.Logf("[%s]        Leap: %d", host, r.Leap)
	t.Logf("[%s]    KissCode: %s", host, stringOrEmpty(r.KissCode))
}

func formatRefID(id uint32, stratum uint8) string {
	if stratum == 0 {
		return "<kiss>"
	}

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, id)

	// Stratum 1 ref IDs typically contain ASCII-encoded string identifiers.
	if stratum == 1 {
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

	// Stratum 2+ ref IDs typically contain IPv4 addresses.
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func stringOrEmpty(s string) string {
	if s == "" {
		return "<empty>"
	}
	return s
}

func TestOnlineBadServerPort(t *testing.T) {
	// Not NTP port.
	tm, _, err := getTime(host+":9", &QueryOptions{Timeout: 1 * time.Second})
	assert.Nil(t, tm)
	assert.NotNil(t, err)
}

func TestOnlineQuery(t *testing.T) {
	r, err := QueryWithOptions(host, QueryOptions{})
	if !isNil(t, host, err) {
		return
	}
	assertValid(t, r)
	logResponse(t, r)
}

func TestOnlineQueryTimeout(t *testing.T) {
	if host == "localhost" {
		t.Skip("Timeout test not available with localhost NTP server.")
		return
	}

	// Force an immediate timeout.
	r, err := QueryWithOptions(host, QueryOptions{Timeout: time.Nanosecond})
	assert.Nil(t, r)
	assert.NotNil(t, err)
}

func TestOnlineTime(t *testing.T) {
	tm, err := Time(host)
	now := time.Now()
	if isNil(t, host, err) {
		t.Logf(" System Time: %s\n", now.Format(timeFormat))
		t.Logf("  ~True Time: %s\n", tm.Format(timeFormat))
		t.Logf("~ClockOffset: %v\n", tm.Sub(now))
	}
}

func TestOnlineTimeFailure(t *testing.T) {
	// Use a link-local IP address that won't have an NTP server listening
	// on it. This should return the local system's time.
	local, err := Time("169.254.122.229")
	assert.NotNil(t, err)

	// When the NTP time query fails, it should return the system time.
	// Compare the "now" system time with the returned time. It should be
	// about the same.
	now := time.Now()
	diffMinutes := now.Sub(local).Minutes()
	assert.True(t, diffMinutes > -1 && diffMinutes < 1)
}

func TestOnlineTTL(t *testing.T) {
	if host == "localhost" {
		t.Skip("TTL test not available with localhost NTP server.")
		return
	}

	// TTL of 1 should cause a timeout.
	hdr, _, err := getTime(host, &QueryOptions{TTL: 1, Timeout: 1 * time.Second})
	assert.Nil(t, hdr)
	assert.NotNil(t, err)
}

func TestOfflineConvertLong(t *testing.T) {
	ts := []ntpTime{0x0, 0xff800000, 0x1ff800000, 0x80000000ff800000, 0xffffffffff800000}
	for _, v := range ts {
		assert.Equal(t, v, toNtpTime(v.Time()))
	}
}

func TestOfflineConvertShort(t *testing.T) {
	cases := []struct {
		NtpTime  ntpTimeShort
		Duration time.Duration
	}{
		{0x00000000, 0 * time.Nanosecond},
		{0x00000001, 15259 * time.Nanosecond},
		{0x00008000, 500 * time.Millisecond},
		{0x0000c000, 750 * time.Millisecond},
		{0x0000ff80, time.Second - (1000000000/512)*time.Nanosecond},
		{0x00010000, 1000 * time.Millisecond},
		{0x00018000, 1500 * time.Millisecond},
		{0xffff0000, 65535 * time.Second},
		{0xffffff80, 65536*time.Second - (1000000000/512)*time.Nanosecond},
	}

	for _, c := range cases {
		ts := c.NtpTime
		assert.Equal(t, c.Duration, ts.Duration())
	}
}

func TestOfflineCustomDialer(t *testing.T) {
	raddr := "remote:123"
	laddr := "local"
	dialerCalled := false
	notDialingErr := errors.New("not dialing")

	customDialer := func(la, ra string) (net.Conn, error) {
		assert.Equal(t, laddr, la)
		assert.Equal(t, raddr, ra)
		// Only expect to be called once:
		assert.False(t, dialerCalled)

		dialerCalled = true
		return nil, notDialingErr
	}

	opt := QueryOptions{
		LocalAddress: laddr,
		Dialer:       customDialer,
	}
	r, err := QueryWithOptions(raddr, opt)
	assert.Nil(t, r)
	assert.Equal(t, notDialingErr, err)
	assert.True(t, dialerCalled)
}

func TestOfflineCustomDialerDeprecated(t *testing.T) {
	raddr := "remote"
	laddr := "local"
	dialerCalled := false
	notDialingErr := errors.New("not dialing")

	customDial := func(la string, lp int, ra string, rp int) (net.Conn, error) {
		assert.Equal(t, laddr, la)
		assert.Equal(t, 0, lp)
		assert.Equal(t, raddr, ra)
		assert.Equal(t, 123, rp)
		// Only expect to be called once:
		assert.False(t, dialerCalled)

		dialerCalled = true
		return nil, notDialingErr
	}

	opt := QueryOptions{
		LocalAddress: laddr,
		Dial:         customDial,
	}
	r, err := QueryWithOptions(raddr, opt)
	assert.Nil(t, r)
	assert.Equal(t, notDialingErr, err)
	assert.True(t, dialerCalled)
}

func TestOfflineKissCode(t *testing.T) {
	codes := []struct {
		id  uint32
		str string
	}{
		{0x41435354, "ACST"},
		{0x41555448, "AUTH"},
		{0x4155544f, "AUTO"},
		{0x42435354, "BCST"},
		{0x43525950, "CRYP"},
		{0x44454e59, "DENY"},
		{0x44524f50, "DROP"},
		{0x52535452, "RSTR"},
		{0x494e4954, "INIT"},
		{0x4d435354, "MCST"},
		{0x4e4b4559, "NKEY"},
		{0x4e54534e, "NTSN"},
		{0x52415445, "RATE"},
		{0x524d4f54, "RMOT"},
		{0x53544550, "STEP"},
		{0x01010101, ""},
		{0xfefefefe, ""},
		{0x01544450, ""},
		{0x41544401, ""},
	}
	for _, c := range codes {
		assert.Equal(t, kissCode(c.id), c.str)
	}
}

func TestOfflineMinError(t *testing.T) {
	start := time.Now()
	m := &header{
		Stratum:       1,
		ReferenceID:   refID,
		ReferenceTime: toNtpTime(start),
		OriginTime:    toNtpTime(start.Add(1 * time.Second)),
		ReceiveTime:   toNtpTime(start.Add(2 * time.Second)),
		TransmitTime:  toNtpTime(start.Add(3 * time.Second)),
	}
	r := generateResponse(m, toNtpTime(start.Add(4*time.Second)), nil)
	assertValid(t, r)
	assert.Equal(t, r.MinError, time.Duration(0))

	for org := 1 * time.Second; org <= 10*time.Second; org += time.Second {
		for rec := 1 * time.Second; rec <= 10*time.Second; rec += time.Second {
			for xmt := rec; xmt <= 10*time.Second; xmt += time.Second {
				for dst := org; dst <= 10*time.Second; dst += time.Second {
					m.OriginTime = toNtpTime(start.Add(org))
					m.ReceiveTime = toNtpTime(start.Add(rec))
					m.TransmitTime = toNtpTime(start.Add(xmt))
					r = generateResponse(m, toNtpTime(start.Add(dst)), nil)
					assertValid(t, r)
					var error0, error1 time.Duration
					if org >= rec {
						error0 = org - rec
					}
					if xmt >= dst {
						error1 = xmt - dst
					}
					var minError time.Duration
					if error0 > error1 {
						minError = error0
					} else {
						minError = error1
					}
					assert.Equal(t, r.MinError, minError)
				}
			}
		}
	}
}

func TestOfflineOffsetCalculation(t *testing.T) {
	now := time.Now()
	t1 := toNtpTime(now)
	t2 := toNtpTime(now.Add(20 * time.Second))
	t3 := toNtpTime(now.Add(21 * time.Second))
	t4 := toNtpTime(now.Add(5 * time.Second))

	// expectedOffset := ((T2 - T1) + (T3 - T4)) / 2
	// ((119 - 99) + (121 - 104)) / 2
	// (20 +  17) / 2
	// 37 / 2 = 18
	expectedOffset := 18 * time.Second
	offset := offset(t1, t2, t3, t4)
	assert.Equal(t, expectedOffset, offset)
}

func TestOfflineOffsetCalculationNegative(t *testing.T) {
	now := time.Now()
	t1 := toNtpTime(now.Add(101 * time.Second))
	t2 := toNtpTime(now.Add(102 * time.Second))
	t3 := toNtpTime(now.Add(103 * time.Second))
	t4 := toNtpTime(now.Add(105 * time.Second))

	// expectedOffset := ((T2 - T1) + (T3 - T4)) / 2
	// ((102 - 101) + (103 - 105)) / 2
	// (1 + -2) / 2 = -1 / 2
	expectedOffset := -time.Second / 2
	offset := offset(t1, t2, t3, t4)
	assert.Equal(t, expectedOffset, offset)
}

func TestOfflineTimeConversions(t *testing.T) {
	nowNtp := toNtpTime(time.Now())
	now := nowNtp.Time()
	startNow := now
	for i := 0; i < 100; i++ {
		nowNtp = toNtpTime(now)
		now = nowNtp.Time()
	}
	assert.Equal(t, now, startNow)
}

func TestOfflineValidate(t *testing.T) {
	var m header
	var r *Response
	m.Stratum = 1
	m.ReferenceID = refID
	m.ReferenceTime = 1 << 32
	m.Precision = -1 // 500ms

	// Zero RTT
	m.OriginTime = 1 << 32
	m.ReceiveTime = 1 << 32
	m.TransmitTime = 1 << 32
	r = generateResponse(&m, 1<<32, nil)
	assertValid(t, r)

	// Negative freshness
	m.ReferenceTime = 2 << 32
	r = generateResponse(&m, 1<<32, nil)
	assertInvalid(t, r)

	// Unfresh clock (48h)
	m.OriginTime = 2 * 86400 << 32
	m.ReceiveTime = 2 * 86400 << 32
	m.TransmitTime = 2 * 86400 << 32
	r = generateResponse(&m, 2*86400<<32, nil)
	assertInvalid(t, r)

	// Fresh clock (24h)
	m.ReferenceTime = 1 * 86400 << 32
	r = generateResponse(&m, 2*86400<<32, nil)
	assertValid(t, r)

	// Values indicating a negative RTT
	m.RootDelay = 16 << 16
	m.ReferenceTime = 1 << 32
	m.OriginTime = 20 << 32
	m.ReceiveTime = 10 << 32
	m.TransmitTime = 15 << 32
	r = generateResponse(&m, 22<<32, nil)
	assert.NotNil(t, r)
	assertValid(t, r)
	assert.Equal(t, r.RTT, 0*time.Second)
	assert.Equal(t, r.RootDistance, 8*time.Second)
}
