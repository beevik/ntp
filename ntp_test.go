// Copyright © 2015-2023 Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ntp

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// The NTP server to use for online unit tests. May be overridden by the
// NTP_HOST environment variable.
var host string = "0.beevik-ntp.pool.ntp.org"

const (
	refID      = 0xc0a80001
	timeFormat = "Mon Jan _2 2006  15:04:05.00000000 (MST)"
)

func init() {
	h := os.Getenv("NTP_HOST")
	if h != "" {
		host = h
	}
}

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
	t.Logf("[%s]       RefID: %s (0x%08x)", host, r.ReferenceString(), r.ReferenceID)
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

func TestOfflineFixHostPort(t *testing.T) {
	const defaultPort = 123

	cases := []struct {
		address string
		fixed   string
		errMsg  string
	}{
		{"192.168.1.1", "192.168.1.1:123", ""},
		{"192.168.1.1:123", "192.168.1.1:123", ""},
		{"192.168.1.1:1000", "192.168.1.1:1000", ""},
		{"[192.168.1.1]:1000", "[192.168.1.1]:1000", ""},
		{"www.example.com", "www.example.com:123", ""},
		{"www.example.com:123", "www.example.com:123", ""},
		{"www.example.com:1000", "www.example.com:1000", ""},
		{"[www.example.com]:1000", "[www.example.com]:1000", ""},
		{"::1", "[::1]:123", ""},
		{"[::1]", "[::1]:123", ""},
		{"[::1]:123", "[::1]:123", ""},
		{"[::1]:1000", "[::1]:1000", ""},
		{"fe80::1", "[fe80::1]:123", ""},
		{"[fe80::1]", "[fe80::1]:123", ""},
		{"[fe80::1]:123", "[fe80::1]:123", ""},
		{"[fe80::1]:1000", "[fe80::1]:1000", ""},
		{"[fe80::", "", "missing ']' in address"},
		{"[fe80::]@", "", "unexpected character following ']' in address"},
		{"ff06:0:0:0:0:0:0:c3", "[ff06:0:0:0:0:0:0:c3]:123", ""},
		{"[ff06:0:0:0:0:0:0:c3]", "[ff06:0:0:0:0:0:0:c3]:123", ""},
		{"[ff06:0:0:0:0:0:0:c3]:123", "[ff06:0:0:0:0:0:0:c3]:123", ""},
		{"[ff06:0:0:0:0:0:0:c3]:1000", "[ff06:0:0:0:0:0:0:c3]:1000", ""},
		{"::ffff:192.168.1.1", "[::ffff:192.168.1.1]:123", ""},
		{"[::ffff:192.168.1.1]", "[::ffff:192.168.1.1]:123", ""},
		{"[::ffff:192.168.1.1]:123", "[::ffff:192.168.1.1]:123", ""},
		{"[::ffff:192.168.1.1]:1000", "[::ffff:192.168.1.1]:1000", ""},
		{"", "", "address string is empty"},
	}
	for _, c := range cases {
		fixed, err := fixHostPort(c.address, defaultPort)
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		assert.Equal(t, c.fixed, fixed)
		assert.Equal(t, c.errMsg, errMsg)
	}
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
	h := &header{
		Stratum:       1,
		ReferenceID:   refID,
		ReferenceTime: toNtpTime(start),
		OriginTime:    toNtpTime(start.Add(1 * time.Second)),
		ReceiveTime:   toNtpTime(start.Add(2 * time.Second)),
		TransmitTime:  toNtpTime(start.Add(3 * time.Second)),
	}
	r := generateResponse(h, toNtpTime(start.Add(4*time.Second)), nil)
	assertValid(t, r)
	assert.Equal(t, r.MinError, time.Duration(0))

	for org := 1 * time.Second; org <= 10*time.Second; org += time.Second {
		for rec := 1 * time.Second; rec <= 10*time.Second; rec += time.Second {
			for xmt := rec; xmt <= 10*time.Second; xmt += time.Second {
				for dst := org; dst <= 10*time.Second; dst += time.Second {
					h.OriginTime = toNtpTime(start.Add(org))
					h.ReceiveTime = toNtpTime(start.Add(rec))
					h.TransmitTime = toNtpTime(start.Add(xmt))
					r = generateResponse(h, toNtpTime(start.Add(dst)), nil)
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

func TestOfflineReferenceString(t *testing.T) {
	cases := []struct {
		Stratum byte
		RefID   uint32
		Str     string
	}{
		{0, 0x41435354, "ACST"},
		{0, 0x41555448, "AUTH"},
		{0, 0x4155544f, "AUTO"},
		{0, 0x42435354, "BCST"},
		{0, 0x43525950, "CRYP"},
		{0, 0x44454e59, "DENY"},
		{0, 0x44524f50, "DROP"},
		{0, 0x52535452, "RSTR"},
		{0, 0x494e4954, "INIT"},
		{0, 0x4d435354, "MCST"},
		{0, 0x4e4b4559, "NKEY"},
		{0, 0x4e54534e, "NTSN"},
		{0, 0x52415445, "RATE"},
		{0, 0x524d4f54, "RMOT"},
		{0, 0x53544550, "STEP"},
		{0, 0x01010101, ""},
		{0, 0xfefefefe, ""},
		{0, 0x01544450, ""},
		{0, 0x41544401, ""},
		{1, 0x47505300, ".GPS."},
		{1, 0x474f4553, ".GOES."},
		{2, 0x0a0a1401, "10.10.20.1"},
		{3, 0xc0a80001, "192.168.0.1"},
		{4, 0xc0a80001, "192.168.0.1"},
		{5, 0xc0a80001, "192.168.0.1"},
		{6, 0xc0a80001, "192.168.0.1"},
		{7, 0xc0a80001, "192.168.0.1"},
		{8, 0xc0a80001, "192.168.0.1"},
		{9, 0xc0a80001, "192.168.0.1"},
		{10, 0xc0a80001, "192.168.0.1"},
	}
	for _, c := range cases {
		r := Response{Stratum: c.Stratum, ReferenceID: c.RefID}
		assert.Equal(t, c.Str, r.ReferenceString())
	}
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
	var h header
	var r *Response
	h.Stratum = 1
	h.ReferenceID = refID
	h.ReferenceTime = 1 << 32
	h.Precision = -1 // 500ms

	// Zero RTT
	h.OriginTime = 1 << 32
	h.ReceiveTime = 1 << 32
	h.TransmitTime = 1 << 32
	r = generateResponse(&h, 1<<32, nil)
	assertValid(t, r)

	// Negative freshness
	h.ReferenceTime = 2 << 32
	r = generateResponse(&h, 1<<32, nil)
	assertInvalid(t, r)

	// Unfresh clock (48h)
	h.OriginTime = 2 * 86400 << 32
	h.ReceiveTime = 2 * 86400 << 32
	h.TransmitTime = 2 * 86400 << 32
	r = generateResponse(&h, 2*86400<<32, nil)
	assertInvalid(t, r)

	// Fresh clock (24h)
	h.ReferenceTime = 1 * 86400 << 32
	r = generateResponse(&h, 2*86400<<32, nil)
	assertValid(t, r)

	// Values indicating a negative RTT
	h.RootDelay = 16 << 16
	h.ReferenceTime = 1 << 32
	h.OriginTime = 20 << 32
	h.ReceiveTime = 10 << 32
	h.TransmitTime = 15 << 32
	r = generateResponse(&h, 22<<32, nil)
	assert.NotNil(t, r)
	assertValid(t, r)
	assert.Equal(t, r.RTT, 0*time.Second)
	assert.Equal(t, r.RootDistance, 8*time.Second)
}
