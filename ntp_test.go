package ntp

import (
	"github.com/stretchr/testify/assert"
	"math"
	"testing"
	"time"
	"fmt"
)

const (
	host  = "0.pool.ntp.org"
	delta = 1.0
)

func TestVersionSelection(t *testing.T) {
	timeV4, err := Time(host)
	if err != nil {
		t.Errorf("NTP V4 request failed: %s", err)
	}
	t.Logf("Got current time from %s %s for NTP version %d", host, timeV4, 4)

	timeV3, err := TimeV(host, 3)
	if err != nil {
		t.Errorf("NTP V3 request failed: %s", err)
	}
	t.Logf("Got current time from %s %s for NTP version %d", host, timeV3, 3)

	timeV2, err := TimeV(host, 2)
	if err != nil {
		t.Errorf("NTP V3 request failed: %s", err)
	}
	t.Logf("Got current time from %s %s for NTP version %d", host, timeV2, 2)

	if timeV2.Sub(timeV3).Seconds() > delta {
		t.Errorf("Difference between NTP version %d and %d time values greaten than %f seconds",
			2, 3, delta)
	}

	if timeV3.Sub(timeV4).Seconds() > delta {
		t.Errorf("Difference between NTP version %d and %d time values greaten than %f seconds",
			3, 4, delta)
	}

	if timeV2.Sub(timeV4).Seconds() > delta {
		t.Errorf("Difference between NTP version %d and %d time values greaten than %f seconds",
			2, 4, delta)
	}
}

func TestNtpTimeSubtract(t *testing.T) {
	// a fraction > b fraction
	a := ntpTime{Seconds: 10, Fraction: 100}
	b := ntpTime{Seconds: 5, Fraction: 50}
	assert.Equal(t, ntpTime{Seconds: 5, Fraction: 50}, a.subtract(b))

	// a fraction < b fraction
	b = ntpTime{Seconds: 5, Fraction: 101}
	assert.Equal(t, ntpTime{Seconds: 4, Fraction: 4294967295}, a.subtract(b)) // fraction over flows

	// a fraction == b fraction
	b = ntpTime{Seconds: 5, Fraction: 100}
	assert.Equal(t, ntpTime{Seconds: 5, Fraction: 0}, a.subtract(b))
}

func TestNtpTimeAdd(t *testing.T) {
	// unsigned 32 bit integer ranges from 0 - 2^32-1. Tests for the edge cases.

	//a fraction + b fraction < 2^32-1
	a := ntpTime{Seconds: 10, Fraction: 100}
	b := ntpTime{Seconds: 5, Fraction: 50}
	assert.Equal(t, ntpTime{Seconds: 15, Fraction: 150}, a.add(b))
	assert.Equal(t, ntpTime{Seconds: 15, Fraction: 150}, b.add(a))

	// a fraction + b fraction > 2^32-1
	halfWay := uint32(math.Pow(2, 32) / 2)
	oneAbove := uint32(halfWay + 1)
	assert.Equal(t, ntpTime{Seconds: 11, Fraction: 1}, ntpTime{Seconds: 5, Fraction: halfWay}.add(ntpTime{Seconds: 5, Fraction: oneAbove}))

	//a fraction + b fraction > 2^32 where b fraction == 2^32-1
	max32BitValue := uint32(math.Pow(2, 32) - 1)
	b = ntpTime{Seconds: 5, Fraction: uint32(max32BitValue)}
	assert.Equal(t, ntpTime{Seconds: 16, Fraction: 99}, b.add(a)) // fraction over flows
	assert.Equal(t, ntpTime{Seconds: 16, Fraction: 99}, a.add(b)) // fraction over flows
	// a fraction + b fraction = 2^32

	//a fraction + b fraction = 2^32
	oneUnder32BitNumber := max32BitValue - 1
	b = ntpTime{Seconds: 5, Fraction: uint32(oneUnder32BitNumber)}
	assert.Equal(t, ntpTime{Seconds: 6, Fraction: max32BitValue}, ntpTime{Seconds: 1, Fraction: 1}.add(b))
}

func TestNtpTimeConversions(t *testing.T) {
	// Test cases taken from https://www.eecis.udel.edu/~mills/y2k.html#ntp
	n := ntpTime{Seconds: 3673001991, Fraction: 2436539606}
	assert.Equal(t, int64(1464013191567301084), n.UTC().UnixNano())
	assert.Equal(t, ntpTime{Seconds: 0, Fraction: 0}, toNtpTime(time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)))
	assert.Equal(t, ntpTime{Seconds: 2208988800, Fraction: 0}, toNtpTime(time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)))
	assert.Equal(t, ntpTime{Seconds: 3673001991, Fraction: 2436539602}, toNtpTime(time.Unix(0, 1464013191567301084)))
	assert.Equal(t, ntpTime{Seconds: 4294944000, Fraction: 0}, toNtpTime(time.Date(2036, 2, 7, 0, 0, 0, 0, time.UTC)))
}

func TestOffsetCalculation(t *testing.T) {
	now := uint32(time.Now().Unix())
	localSent := ntpTime{Seconds: now, Fraction: 0}
	serverReceive := ntpTime{Seconds: now + 20, Fraction: 0}
	serverReply := ntpTime{Seconds: now + 21, Fraction: 0}
	localReceive := ntpTime{Seconds: now + 5, Fraction: 0}
	// ((119 - 99) + (121 - 104)) / 2
	// (20 +  17) / 2
	// 37 / 2 = 18
	//expectedOffset := int(((serverReceive - localSent) + (serverReply - localReceive)) / 2)
	expectedOffset := uint64(18 * 1e9) // nano seconds so * 1billion
	offset, _ := offset(
		localSent,
		serverReceive,
		serverReply,
		localReceive)

	assert.Equal(t, expectedOffset, offset)
}

func TestOffset(t *testing.T) {
	o, err := Offset(host)
	assert.NoError(t, err)
	// Relies on your computer being within delta of the NTP server
	assert.True(t, math.Abs(float64(o)) < float64(delta*time.Second), "Expected small offset %d", o)
}
