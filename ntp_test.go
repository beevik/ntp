package ntp

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	host  = "0.pool.ntp.org"
	delta = 1.0
)

func TestTime(t *testing.T) {
	tm, err := Time(host)
	if err != nil {
		t.Error(err)
	}
	t.Logf("%v\n", tm)
}

func TestTimeTimeout(t *testing.T) {
	old := timeout
	timeout = 1 * time.Nanosecond
	tm, err := Time(host)
	assert.NotNil(t, tm) // for some non-obvious reason it's time.Now() in case of err
	assert.NotNil(t, err)
	timeout = old
}

func TestQuery(t *testing.T) {
	for version := 2; version <= 4; version++ {
		testQueryVersion(version, t)
	}
}

func TestQueryTimeout(t *testing.T) {
	old := timeout
	timeout = 1 * time.Nanosecond
	tm, err := Query(host, 4)
	assert.Nil(t, tm)
	assert.NotNil(t, err)
	timeout = old
}

func TestGetTimeTimeout(t *testing.T) {
	old := timeout
	timeout = 1 * time.Nanosecond
	tm, err := getTime(host, 4)
	assert.Nil(t, tm)
	assert.NotNil(t, err)
	timeout = old
}

func testQueryVersion(version int, t *testing.T) {
	t.Logf("[%s] ----------------------", host)
	t.Logf("[%s] NTP protocol version %d", host, version)

	r, err := Query(host, version)
	if err != nil {
		// Don't treat timeouts like errors, because timeouts are common.
		if strings.Contains(err.Error(), "i/o timeout") {
			t.Logf("[%s] Query timeout: %s", host, err)
		} else {
			t.Errorf("[%s] Query failed: %s", host, err)
		}
		return
	}

	if r.Stratum < 1 || r.Stratum > 16 {
		t.Errorf("[%s] Invalid stratum: %d", host, r.Stratum)
	}

	if abs(r.ClockOffset) > time.Second {
		t.Errorf("[%s] Large clock offset: %v", host, r.ClockOffset)
	}

	if r.RTT < time.Duration(0) {
		t.Errorf("[%s] Negative round trip time: %v", host, r.RTT)
	}

	t.Logf("[%s]       Time: %v", host, r.Time)
	t.Logf("[%s]    RefTime: %v", host, r.ReferenceTime) // it's displayed in UTC as NTP has no timezones
	t.Logf("[%s]        RTT: %v", host, r.RTT)
	t.Logf("[%s]     Offset: %v", host, r.ClockOffset)
	t.Logf("[%s]       Poll: %v", host, r.Poll)
	t.Logf("[%s]  Precision: %v", host, r.Precision)
	t.Logf("[%s]    Stratum: %v", host, r.Stratum)
	t.Logf("[%s]      RefID: 0x%08x", host, r.ReferenceID)
	t.Logf("[%s]  RootDelay: %v", host, r.RootDelay)
	t.Logf("[%s]   RootDisp: %v", host, r.RootDispersion)
	t.Logf("[%s]       Leap: %v", host, r.Leap)
}

func TestShortConversion(t *testing.T) {
	var ts ntpTimeShort

	ts = 0x00000000
	assert.Equal(t, 0*time.Nanosecond, ts.Duration())

	ts = 0x00000001
	assert.Equal(t, 15258*time.Nanosecond, ts.Duration()) // well, it's actually 15258.789, but it's good enough

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

func TestLongConversion(t *testing.T) {
	ts := []ntpTime{0x0, 0xff800000, 0x1ff800000, 0x80000000ff800000, 0xffffffffff800000}

	for _, v := range ts {
		assert.Equal(t, v, toNtpTime(v.Time()))
	}
}

func abs(d time.Duration) time.Duration {
	switch {
	case int64(d) < 0:
		return -d
	default:
		return d
	}
}

func TestOffsetCalculation(t *testing.T) {
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

func TestOffsetCalculationNegative(t *testing.T) {
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
