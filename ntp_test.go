package ntp

import (
	"testing"
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
		t.Errorf("NTP V2 request failed: %s", err)
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

func TestStratum(t *testing.T) {
	for _, version := range []uint8{2, 3, 4} {
		r, err := Query(host, version)
		if err != nil {
			t.Errorf("NTP V%d request failed: %s", version, err)
		}
		// pool.ntp.org servers should almost certainly have stratum 10 or less.
		if r.Stratum < 1 || r.Stratum > 10 {
			t.Errorf("Invalid stratum from %s: %d", host, r.Stratum)
		}
	}
}
