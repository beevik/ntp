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

func TestQuery(t *testing.T) {
	for version := 2; version <= 4; version++ {
		testQueryVersion(version, t)
	}
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

	t.Logf("[%s]       Time: %v", host, r.Time.Local())
	t.Logf("[%s]        RTT: %v", host, r.RTT)
	t.Logf("[%s]     Offset: %v", host, r.ClockOffset)
	t.Logf("[%s]       Poll: %v", host, r.Poll)
	t.Logf("[%s]  Precision: %v", host, r.Precision)
	t.Logf("[%s]    Stratum: %v", host, r.Stratum)
	t.Logf("[%s]      RefID: 0x%08x", host, r.ReferenceID)
	t.Logf("[%s]  RootDelay: %v", host, r.RootDelay)
	t.Logf("[%s]   RootDisp: %v", host, r.RootDispersion)
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
