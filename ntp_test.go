package ntp

import (
	"testing"
)

const (
	host  = "0.pool.ntp.org"
	delta = 0.2
)

func TestVersionSelection(t *testing.T) {
	timeV4, err := Time(host)
	if err != nil {
		t.Errorf("NTP V4 request failed: %s", err)
	}
	t.Logf("Got current time from %s %s for NTP version %d", host, timeV4, V4)

	Version = V3
	timeV3, err := Time(host)
	if err != nil {
		t.Errorf("NTP V3 request failed: %s", err)
	}
	t.Logf("Got current time from %s %s for NTP version %d", host, timeV3, V3)

	Version = V2
	timeV2, err := Time(host)
	if err != nil {
		t.Errorf("NTP V3 request failed: %s", err)
	}
	t.Logf("Got current time from %s %s for NTP version %d", host, timeV2, V2)

	if timeV2.Sub(timeV3).Seconds() > delta {
		t.Errorf("Difference between NTP version %d and %d time values greaten than %f seconds",
			V2, V3, delta)
	}

	if timeV3.Sub(timeV4).Seconds() > delta {
		t.Errorf("Difference between NTP version %d and %d time values greaten than %f seconds",
			V3, V4, delta)
	}

	if timeV2.Sub(timeV4).Seconds() > delta {
		t.Errorf("Difference between NTP version %d and %d time values greaten than %f seconds",
			V2, V4, delta)
	}
}
