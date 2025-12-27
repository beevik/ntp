// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ntp

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func logResponseV4(t *testing.T, r *Response) {
	now := time.Now()
	t.Logf("[%s] ClockOffset: %s", host, r.ClockOffset)
	t.Logf("[%s]  SystemTime: %s", host, now.Format(timeFormat))
	t.Logf("[%s]   ~TrueTime: %s", host, now.Add(r.ClockOffset).Format(timeFormat))
	t.Logf("[%s]    XmitTime: %s", host, r.Time.Format(timeFormat))
	t.Logf("[%s]     Version: %d", host, r.Version)
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
	t.Logf("[%s]       Flags: 0x%08x", host, r.Flags)
	t.Logf("[%s]    KissCode: %s", host, stringOrEmpty(r.KissCode))
}

func TestOnlineBadServerPort(t *testing.T) {
	// Not NTP port.
	r, err := QueryWithOptions(host+":9", QueryOptions{Timeout: 1 * time.Second})
	assert.Nil(t, r)
	assert.NotNil(t, err)
}

func TestOnlineV3Query(t *testing.T) {
	r, err := QueryWithOptions(host, QueryOptions{Version: 3})
	if isError(t, host, err) {
		return
	}
	assertValid(t, r)
	logResponseV4(t, r)
}

func TestOnlineV4Query(t *testing.T) {
	r, err := QueryWithOptions(host, QueryOptions{Version: 4})
	if isError(t, host, err) {
		return
	}
	assertValid(t, r)
	logResponseV4(t, r)
}

func TestOnlineV4QueryTimeout(t *testing.T) {
	if host == "localhost" {
		t.Skip("Timeout test not available with localhost NTP server.")
		return
	}

	// Force an immediate timeout.
	r, err := QueryWithOptions(host, QueryOptions{Timeout: time.Nanosecond})
	assert.Nil(t, r)
	assert.NotNil(t, err)
}

func TestOnlineV4Time(t *testing.T) {
	tm, err := Time(host)
	now := time.Now()
	if !isError(t, host, err) {
		t.Logf(" System Time: %s\n", now.Format(timeFormat))
		t.Logf("  ~True Time: %s\n", tm.Format(timeFormat))
		t.Logf("~ClockOffset: %v\n", tm.Sub(now))
	}
}

func TestOnlineV4TimeFailure(t *testing.T) {
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

func TestOnlineV4TTL(t *testing.T) {
	if host == "localhost" {
		t.Skip("TTL test not available with localhost NTP server.")
		return
	}

	// TTL of 1 should cause a timeout.
	r, err := QueryWithOptions(host, QueryOptions{TTL: 1, Timeout: 1 * time.Second})
	assert.Nil(t, r)
	assert.NotNil(t, err)
}

func TestOnlineV4CustomGetSystemTime(t *testing.T) {
	if host == "localhost" {
		t.Skip("Timeout test not available with localhost NTP server.")
		return
	}

	var simuTime atomic.Value
	simuTime.Store(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))

	const timerInterval = 1 * time.Millisecond
	ctx := t.Context()

	// Start a simulated clock independent of the system wall clock,
	// initialized at 2020-01-01T00:00:00, advancing in 1 ms increments.
	go func() {
		ticker := time.NewTicker(timerInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				current := simuTime.Load().(time.Time)
				simuTime.Store(current.Add(timerInterval))
			}
		}
	}()

	r, err := QueryWithOptions(host, QueryOptions{
		GetSystemTime: func() time.Time { return simuTime.Load().(time.Time) },
	})
	if !isError(t, host, err) {
		tm := simuTime.Load().(time.Time)
		trueTime := tm.Add(r.ClockOffset)
		t.Logf(" Custom Time: %s\n", tm.Format(timeFormat))
		t.Logf("  ~True Time: %s\n", trueTime.Format(timeFormat))
		t.Logf("~ClockOffset: %v\n", trueTime.Sub(tm))
	}
}

func TestOfflineV4ConvertLong(t *testing.T) {
	ts := []timestamp{0x0, 0xff800000, 0x1ff800000, 0x80000000ff800000, 0xffffffffff800000}
	for _, v := range ts {
		assert.Equal(t, v, toTimestamp(v.TimeV4()))
	}
}

func TestOfflineV4ConvertShort(t *testing.T) {
	cases := []struct {
		Time     timeShortV4
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
		ts := c.Time
		assert.Equal(t, c.Duration, ts.Duration())
	}
}

func TestOfflineV4CustomDialer(t *testing.T) {
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

func TestOfflineV4CustomDialerDeprecated(t *testing.T) {
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

func TestOfflineV4MinError(t *testing.T) {
	start := time.Now()
	m := &messageV4{
		Stratum:       1,
		ReferenceID:   refID,
		ReferenceTime: toTimestamp(start),
		OriginTime:    toTimestamp(start.Add(1 * time.Second)),
		ReceiveTime:   toTimestamp(start.Add(2 * time.Second)),
		TransmitTime:  toTimestamp(start.Add(3 * time.Second)),
	}
	r := generateResponse(m, toTimestamp(start.Add(4*time.Second)), nil)
	assertValid(t, r)
	assert.Equal(t, r.MinError, time.Duration(0))

	for org := 1 * time.Second; org <= 10*time.Second; org += time.Second {
		for rec := 1 * time.Second; rec <= 10*time.Second; rec += time.Second {
			for xmt := rec; xmt <= 10*time.Second; xmt += time.Second {
				for dst := org; dst <= 10*time.Second; dst += time.Second {
					m.OriginTime = toTimestamp(start.Add(org))
					m.ReceiveTime = toTimestamp(start.Add(rec))
					m.TransmitTime = toTimestamp(start.Add(xmt))
					r = generateResponse(m, toTimestamp(start.Add(dst)), nil)
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

func TestOfflineV4OffsetCalculation(t *testing.T) {
	now := time.Now()
	t1 := toTimestamp(now)
	t2 := toTimestamp(now.Add(20 * time.Second))
	t3 := toTimestamp(now.Add(21 * time.Second))
	t4 := toTimestamp(now.Add(5 * time.Second))

	// expectedOffset := ((T2 - T1) + (T3 - T4)) / 2
	// ((119 - 99) + (121 - 104)) / 2
	// (20 +  17) / 2
	// 37 / 2 = 18
	expectedOffset := 18 * time.Second
	offset := offset(t1, t2, t3, t4)
	assert.Equal(t, expectedOffset, offset)
}

func TestOfflineV4OffsetCalculationNegative(t *testing.T) {
	now := time.Now()
	t1 := toTimestamp(now.Add(101 * time.Second))
	t2 := toTimestamp(now.Add(102 * time.Second))
	t3 := toTimestamp(now.Add(103 * time.Second))
	t4 := toTimestamp(now.Add(105 * time.Second))

	// expectedOffset := ((T2 - T1) + (T3 - T4)) / 2
	// ((102 - 101) + (103 - 105)) / 2
	// (1 + -2) / 2 = -1 / 2
	expectedOffset := -time.Second / 2
	offset := offset(t1, t2, t3, t4)
	assert.Equal(t, expectedOffset, offset)
}

func TestOfflineV4OffsetRollover(t *testing.T) {
	cases := []struct {
		clientTime string
		serverTime string
	}{
		// both timestamps in NTP era 0 (with large difference)
		{"1970-01-01 00:00:00", "2024-05-30 00:00:00"},
		{"2024-05-30 00:00:00", "1970-01-01 00:00:00"},

		// one timestamp in NTP era 0 and another in era 1
		{"2047-01-01 00:00:00", "2024-01-01 00:00:00"},
		{"2024-01-01 00:00:00", "2047-01-01 00:00:00"},

		// both timestamps in NTP era 1
		{"2047-01-01 00:00:00", "2047-02-01 00:00:00"},
		{"2047-02-01 00:00:00", "2047-01-01 00:00:00"},
	}

	timeFormat := "2006-01-02 15:04:05"

	for _, c := range cases {
		clientTime, _ := time.Parse(timeFormat, c.clientTime)
		serverTime, _ := time.Parse(timeFormat, c.serverTime)

		org := toTimestamp(clientTime)
		rec := toTimestamp(serverTime)
		xmt := toTimestamp(serverTime.Add(1 * time.Second))
		dst := toTimestamp(clientTime.Add(1 * time.Second))

		expectedValue := serverTime.Sub(clientTime)
		value := offset(org, rec, xmt, dst)
		assert.Equal(t, expectedValue, value)
	}
}

func TestOfflineV4TimeRollover(t *testing.T) {
	cases := []struct {
		timestamp timestamp
		time      string
	}{
		{0x0000000000000000, "2036-02-07 06:28:16"},
		{0x0000000100000000, "2036-02-07 06:28:17"},
		{0x1000000000000000, "2044-08-10 03:52:32"},
		{0x2000000000000000, "2053-02-11 01:16:48"},
		{0x3000000000000000, "2061-08-14 22:41:04"},
		{0x4000000000000000, "2070-02-15 20:05:20"},
		{0x5000000000000000, "2078-08-19 17:29:36"},
		{0x6000000000000000, "2087-02-20 14:53:52"},
		{0x7000000000000000, "2095-08-24 12:18:08"},
		{0x8000000000000000, "2104-02-26 09:42:24"},
		{0x83aa7e7000000000, "2106-02-07 06:28:00"},
		{0x83aa7e8000000000, "1970-01-01 00:00:00"}, // <- ntpTime.Time() wrap
		{0x9000000000000000, "1976-07-23 00:38:24"},
		{0xa000000000000000, "1985-01-23 22:02:40"},
		{0xb000000000000000, "1993-07-27 19:26:56"},
		{0xc000000000000000, "2002-01-28 16:51:12"},
		{0xd000000000000000, "2010-08-01 14:15:28"},
		{0xe000000000000000, "2019-02-02 11:39:44"},
		{0xf000000000000000, "2027-08-06 09:04:00"},
		{0xffffffff00000000, "2036-02-07 06:28:15"},
	}

	timeFormat := "2006-01-02 15:04:05"

	for _, c := range cases {
		tm, _ := time.Parse(timeFormat, c.time)
		assert.Equal(t, tm, c.timestamp.TimeV4())
		assert.Equal(t, c.timestamp, toTimestamp(tm))
	}
}

func TestOfflineV4ReferenceString(t *testing.T) {
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

func TestOfflineV4TimeConversions(t *testing.T) {
	tsNow := toTimestamp(time.Now())
	now := tsNow.TimeV4()
	startNow := now
	for range 100 {
		tsNow = toTimestamp(now)
		now = tsNow.TimeV4()
	}
	assert.Equal(t, now, startNow)
}

func TestOfflineV4Validate(t *testing.T) {
	var m messageV4
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
