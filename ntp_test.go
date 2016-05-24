package ntp

import (
	"github.com/stretchr/testify/assert"
	"math"
	"testing"
	"time"
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
	localSent := int64(99)
	serverReceive := int64(119)
	serverReply := int64(121)
	localReceive := int64(104)
	// ((119 - 99) + (121 - 104)) / 2
	// (20 +  17) / 2
	// 37 / 2 = 18
	//expectedOffset := int(((serverReceive - localSent) + (serverReply - localReceive)) / 2)

	expectedOffset := 18
	offset, _ := offset(
		time.Unix(0, localSent),
		time.Unix(0, serverReceive),
		time.Unix(0, serverReply),
		time.Unix(0, localReceive))

	assert.Equal(t, expectedOffset, offset)
}

func TestOffset(t *testing.T) {
	o, err := Offset(host)
	assert.NoError(t, err)
	// Relies on your computer being within 500ms of the NTP server
	assert.True(t, math.Abs(float64(o)) < float64(delta*time.Second), "Expected small offset")
}
