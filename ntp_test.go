package ntp

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	host = "0.beevik-ntp.pool.ntp.org"
)

func TestTime(t *testing.T) {
	tm, err := Time(host)
	now := time.Now()
	if err != nil {
		t.Error(err)
	}
	t.Logf("Local Time %v\n", now)
	t.Logf("~True Time %v\n", tm)
	t.Logf("Offset %v\n", tm.Sub(now))
}

func TestTimeFailure(t *testing.T) {
	local, err := Time("169.254.122.229") // random link-local IPv4 addr that unlikely has ntpd listening at :)
	assert.NotNil(t, err)
	remote, err := Time(host)
	assert.Nil(t, err)
	diffMinutes := remote.Sub(local).Minutes()
	assert.True(t, -15 <= diffMinutes && diffMinutes <= 15) // no TZ errors
}

func TestQuery(t *testing.T) {
	for version := 2; version <= 4; version++ {
		testQueryVersion(version, t)
	}
}

func TestValidate(t *testing.T) {
	var m msg
	var r *Response
	r = parseTime(&m, 0)
	assert.False(t, r.Validate())
	m.Stratum = 1
	m.ReferenceID = 0x58585858 // `XXXX`
	m.ReferenceTime = 1 << 32

	m.OriginTime = 1 << 32
	m.ReceiveTime = 1 << 32
	m.TransmitTime = 1 << 32
	r = parseTime(&m, 1<<32)
	assert.True(t, r.Validate())

	m.ReferenceTime = 2 << 32 // negative freshness
	r = parseTime(&m, 1<<32)
	assert.False(t, r.Validate())

	m.OriginTime = 2 * 86400 << 32
	m.ReceiveTime = 2 * 86400 << 32
	m.TransmitTime = 2 * 86400 << 32
	r = parseTime(&m, 2*86400<<32) // 48h freshness
	assert.False(t, r.Validate())

	m.ReferenceTime = 1 * 86400 << 32 // 24h freshness
	r = parseTime(&m, 2*86400<<32)
	assert.True(t, r.Validate())

	m.RootDelay = 16 << 16
	m.ReferenceTime = 1 << 32
	m.OriginTime = 20 << 32
	m.ReceiveTime = 10 << 32
	m.TransmitTime = 15 << 32
	r = parseTime(&m, 22<<32)
	assert.NotNil(t, r)
	assert.True(t, r.Validate()) // despite negative RTT!
	assert.Equal(t, r.RTT, -3*time.Second)
	assert.Equal(t, r.rootDistance(), 8*time.Second)        // does not account negative RTT
	assert.Equal(t, r.causalityViolation(), 10*time.Second) // OriginTime / ReceiveTime
}

func TestCausality(t *testing.T) {
	var m msg
	var r *Response

	m.Stratum = 1
	m.ReferenceID = 0x58585858 // `XXXX`
	m.ReferenceTime = 1 << 32

	m.OriginTime = 1 << 32
	m.ReceiveTime = 2 << 32
	m.TransmitTime = 3 << 32
	r = parseTime(&m, 4<<32)
	assert.True(t, r.Validate())
	assert.Equal(t, r.causalityViolation(), time.Duration(0))

	var t1, t2, t3, t4 int64
	for t1 = 1; t1 <= 10; t1++ {
		for t2 = 1; t2 <= 10; t2++ {
			for t3 = 1; t3 <= 10; t3++ {
				for t4 = 1; t4 <= 10; t4++ {
					m.OriginTime = ntpTime(t1 << 32)
					m.ReceiveTime = ntpTime(t2 << 32)
					m.TransmitTime = ntpTime(t3 << 32)
					r = parseTime(&m, ntpTime(t4<<32))
					if t1 <= t4 && t2 <= t3 { // anything else is invalid getTime() response
						assert.True(t, r.Validate()) // NB: negative RTT is still possible
						var d12, d34 int64
						if t1 >= t2 {
							d12 = t1 - t2
						}
						if t3 >= t4 {
							d34 = t3 - t4
						}
						var caserr int64
						if d12 > d34 {
							caserr = d12
						} else {
							caserr = d34
						}
						assert.Equal(t, r.causalityViolation(), time.Duration(caserr)*time.Second)
					}
				}
			}
		}
	}
}

func TestServerPort(t *testing.T) {
	tm, _, err := getTime(host, QueryOptions{Port: 9}) // `discard` service
	assert.Nil(t, tm)
	// it may be `read: connection refused`, it may be timeout
	assert.NotNil(t, err)
}

func TestTTL(t *testing.T) {
	tm, _, err := getTime(host, QueryOptions{TTL: 1}) // pool host is unlikely within LAN
	assert.Nil(t, tm)
	assert.NotNil(t, err)
	tm, _, err = getTime(host, QueryOptions{TTL: 255}) // max TTL should reach everything
	assert.NotNil(t, tm)
	assert.Nil(t, err)
}

func TestQueryTimeout(t *testing.T) {
	tm, err := QueryWithOptions(host, QueryOptions{Version: 4, Timeout: time.Nanosecond})
	assert.Nil(t, tm)
	assert.NotNil(t, err)
}

func TestGetTimeTimeout(t *testing.T) {
	tm, _, err := getTime(host, QueryOptions{Version: 4, Timeout: time.Nanosecond})
	assert.Nil(t, tm)
	assert.NotNil(t, err)
}

func TestTimeOrdering(t *testing.T) {
	tm, DestinationTime, err := getTime(host, QueryOptions{})
	assert.Nil(t, err)
	assert.True(t, tm.OriginTime <= DestinationTime)  // local clock tick forward
	assert.True(t, tm.ReceiveTime <= tm.TransmitTime) // server clock tick forward
}

func testQueryVersion(version int, t *testing.T) {
	t.Logf("[%s] ----------------------", host)
	t.Logf("[%s] NTP protocol version %d", host, version)

	r, err := QueryWithOptions(host, QueryOptions{Version: version})
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

	t.Logf("[%s] Local Time: %v", host, time.Now())
	t.Logf("[%s]   xmt Time: %v", host, r.Time)
	t.Logf("[%s]    RefTime: %v", host, r.ReferenceTime) // it's displayed in UTC as NTP has no timezones
	t.Logf("[%s]        RTT: %v", host, r.RTT)
	t.Logf("[%s]     Offset: %v", host, r.ClockOffset)
	t.Logf("[%s] !Causality: %v", host, r.causalityViolation())
	t.Logf("[%s]       Poll: %v", host, r.Poll)
	t.Logf("[%s]  Precision: %v", host, r.Precision)
	t.Logf("[%s]    Stratum: %v", host, r.Stratum)
	t.Logf("[%s]      RefID: 0x%08x", host, r.ReferenceID)
	t.Logf("[%s]  RootDelay: %v", host, r.RootDelay)
	t.Logf("[%s]   RootDisp: %v", host, r.RootDispersion)
	t.Logf("[%s]   RootDist: %v", host, r.rootDistance())
	t.Logf("[%s]       Leap: %v", host, r.Leap)

	assert.True(t, r.Validate())
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
