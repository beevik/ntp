// Copyright 2015-2023 Brett Vickers.
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

const (
	host  = "0.beevik-ntp.pool.ntp.org"
	refID = 0x58585858 // 'XXXX'
)

func isNil(t *testing.T, err error) bool {
	switch {
	case err == nil:
		return true
	case strings.Contains(err.Error(), "timeout"):
		// log instead of error, so test isn't failed
		t.Logf("[%s] Query timeout: %s", host, err)
		return false
	case strings.Contains(err.Error(), "kiss of death"):
		// log instead of error, so test isn't failed
		t.Logf("[%s] Query kiss of death: %s", host, err)
		return false
	default:
		// error, so test fails
		t.Errorf("[%s] Query failed: %s", host, err)
		return false
	}
}

func assertValid(t *testing.T, r *Response) {
	err := r.Validate()
	_ = isNil(t, err)
}

func assertInvalid(t *testing.T, r *Response) {
	err := r.Validate()
	if err == nil {
		t.Errorf("[%s] Response unexpectedly valid\n", host)
	}
}

func TestOnlineTime(t *testing.T) {
	tm, err := Time(host)
	now := time.Now()
	if isNil(t, err) {
		t.Logf("Local Time %v\n", now)
		t.Logf("~True Time %v\n", tm)
		t.Logf("Offset %v\n", tm.Sub(now))
	}
}

func TestOnlineTimeFailure(t *testing.T) {
	// Use a link-local IP address that won't have an NTP server listening
	// on it. This should return the local system's time.
	local, err := Time("169.254.122.229")
	assert.NotNil(t, err)

	now := time.Now()

	// When the NTP time query fails, it should return the system time.
	// Compare the "now" system time with the returned time. It should be
	// about the same.
	diffMinutes := now.Sub(local).Minutes()
	assert.True(t, diffMinutes > -1 && diffMinutes < 1)
}

func TestOnlineQuery(t *testing.T) {
	t.Logf("[%s] ----------------------", host)
	t.Logf("[%s] NTP protocol version %d", host, 4)

	r, err := QueryWithOptions(host, QueryOptions{Version: 4})
	if !isNil(t, err) {
		return
	}

	t.Logf("[%s]  LocalTime: %v", host, time.Now())
	t.Logf("[%s]   XmitTime: %v", host, r.Time)
	t.Logf("[%s]    RefTime: %v", host, r.ReferenceTime)
	t.Logf("[%s]        RTT: %v", host, r.RTT)
	t.Logf("[%s]     Offset: %v", host, r.ClockOffset)
	t.Logf("[%s]       Poll: %v", host, r.Poll)
	t.Logf("[%s]  Precision: %v", host, r.Precision)
	t.Logf("[%s]    Stratum: %v", host, r.Stratum)
	t.Logf("[%s]      RefID: 0x%08x", host, r.ReferenceID)
	t.Logf("[%s]  RootDelay: %v", host, r.RootDelay)
	t.Logf("[%s]   RootDisp: %v", host, r.RootDispersion)
	t.Logf("[%s]   RootDist: %v", host, r.RootDistance)
	t.Logf("[%s]   MinError: %v", host, r.MinError)
	t.Logf("[%s]       Leap: %v", host, r.Leap)
	t.Logf("[%s]   KissCode: %v", host, stringOrEmpty(r.KissCode))

	assertValid(t, r)
}

func stringOrEmpty(s string) string {
	if s == "" {
		return "<empty>"
	}
	return s
}

func TestOfflineValidate(t *testing.T) {
	var m msg
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

func TestOnlineBadServerPort(t *testing.T) {
	// Not NTP port.
	tm, _, err := getTime(host, QueryOptions{Port: 9})
	assert.Nil(t, tm)
	assert.NotNil(t, err)
}

func TestOnlineTTL(t *testing.T) {
	// TTL of 1 should cause a timeout.
	tm, _, err := getTime(host, QueryOptions{TTL: 1})
	assert.Nil(t, tm)
	assert.NotNil(t, err)
}

func TestOnlineQueryTimeout(t *testing.T) {
	// Force an immediate timeout.
	tm, err := QueryWithOptions(host, QueryOptions{Version: 4, Timeout: time.Nanosecond})
	assert.Nil(t, tm)
	assert.NotNil(t, err)
}

func TestOfflineShortConversion(t *testing.T) {
	var ts ntpTimeShort

	ts = 0x00000000
	assert.Equal(t, 0*time.Nanosecond, ts.Duration())

	ts = 0x00000001
	assert.Equal(t, 15259*time.Nanosecond, ts.Duration()) // well, it's actually 15258.789, but it's good enough

	ts = 0x00008000
	assert.Equal(t, 500*time.Millisecond, ts.Duration()) // precise

	ts = 0x0000c000
	assert.Equal(t, 750*time.Millisecond, ts.Duration()) // precise

	ts = 0x0000ff80
	assert.Equal(t, time.Second-(1000000000/512)*time.Nanosecond, ts.Duration()) // last precise sub-second value

	ts = 0x00010000
	assert.Equal(t, 1000*time.Millisecond, ts.Duration()) // precise

	ts = 0x00018000
	assert.Equal(t, 1500*time.Millisecond, ts.Duration()) // precise

	ts = 0xffff0000
	assert.Equal(t, 65535*time.Second, ts.Duration()) // precise

	ts = 0xffffff80
	assert.Equal(t, 65536*time.Second-(1000000000/512)*time.Nanosecond, ts.Duration()) // last precise value
}

func TestOfflineLongConversion(t *testing.T) {
	ts := []ntpTime{0x0, 0xff800000, 0x1ff800000, 0x80000000ff800000, 0xffffffffff800000}

	for _, v := range ts {
		assert.Equal(t, v, toNtpTime(v.Time()))
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

func TestOfflineMinError(t *testing.T) {
	start := time.Now()
	m := &msg{
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

func TestOfflineCustomDialer(t *testing.T) {
	raddr := "remote"
	laddr := "local"
	dialerCalled := false
	notDialingErr := errors.New("not dialing")

	customDialer := func(la string, lp int, ra string, rp int) (net.Conn, error) {
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
		Dial:         customDialer,
	}
	r, err := QueryWithOptions(raddr, opt)
	assert.Nil(t, r)
	assert.Equal(t, notDialingErr, err)
	assert.True(t, dialerCalled)
}

func TestOnlineAuthenticatedQuery(t *testing.T) {
	// By default, this unit test is skipped, because it requires a local NTP
	// server to be running and configured with known symmetric authentication
	// keys.
	//
	// To run this test, you must execute go test with "-args test_auth". For
	// example:
	//
	//    go test -v -args test_auth
	//
	// You must also run a localhost NTP server configured with the following
	// trusted symmetric keys:
	//
	// ID   TYPE    KEY
	// --   ----    ---
	// 1    md5     cvuZyN4C8HX8hNcAWDWp
	// 2    sha1    i1VKJZPEvlU5k0elvf1l
	// 3    sha256  q3snwpWvBVww9pjU32ad
	// 4    sha512  YvuUTFXXhIMDuCBYqRnt

	skip := true
	for _, arg := range os.Args[1:] {
		if arg == "test_auth" {
			skip = false
		}
	}
	if skip {
		t.Skip("Skipping authentication tests. Enable with -args test_auth")
		return
	}

	cases := []struct {
		Type        AuthType
		Key         string
		KeyID       uint16
		ExpectedErr error
	}{
		{AuthMD5, "cvuZyN4C8HX8hNcAWDWp", 1, nil},
		{AuthMD5, "", 1, ErrAuthFailed},
		{AuthMD5, "XvuZyN4C8HX8hNcAWDWp", 1, ErrAuthFailed},
		{AuthMD5, "cvuZyN4C8HX8hNcAWDWp", 2, ErrAuthFailed},
		{AuthSHA1, "cvuZyN4C8HX8hNcAWDWp", 1, ErrAuthFailed},

		{AuthSHA1, "i1VKJZPEvlU5k0elvf1l", 2, nil},
		{AuthSHA1, "", 2, ErrAuthFailed},
		{AuthSHA1, "X1VKJZPEvlU5k0elvf1l", 2, ErrAuthFailed},
		{AuthSHA1, "i1VKJZPEvlU5k0elvf1l", 1, ErrAuthFailed},
		{AuthMD5, "i1VKJZPEvlU5k0elvf1l", 2, ErrAuthFailed},

		{AuthSHA256, "q3snwpWvBVww9pjU32ad", 3, nil},
		{AuthSHA256, "", 3, ErrAuthFailed},
		{AuthSHA256, "X3snwpWvBVww9pjU32ad", 3, ErrAuthFailed},
		{AuthSHA256, "X3snwpWvBVww9pjU32ad", 2, ErrAuthFailed},
		{AuthSHA1, "X3snwpWvBVww9pjU32ad", 3, ErrAuthFailed},

		{AuthSHA512, "YvuUTFXXhIMDuCBYqRnt", 4, nil},
		{AuthSHA512, "", 4, ErrAuthFailed},
		{AuthSHA512, ".vuUTFXXhIMDuCBYqRnt", 4, ErrAuthFailed},
		{AuthSHA512, "YvuUTFXXhIMDuCBYqRnt", 3, ErrAuthFailed},
		{AuthSHA256, "YvuUTFXXhIMDuCBYqRnt", 4, ErrAuthFailed},
	}

	for i, c := range cases {
		opt := QueryOptions{
			Auth: AuthOptions{c.Type, c.Key, c.KeyID},
		}
		r, err := QueryWithOptions("localhost", opt)
		if err != nil {
			t.Errorf("case %d: unexpected error [%v]\n", i, err)
		} else {
			err = r.Validate()
			if err != c.ExpectedErr {
				t.Errorf("case %d: expected error [%v], got [%v]\n", i, c.ExpectedErr, err)
			}
		}
	}
}
