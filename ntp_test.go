package ntp

import (
	"testing"
	"time"
)

const (
	host = "0.pool.ntp.org"
)

func TestQuery(t *testing.T) {
	timeout = 60 * time.Second

	const delta = 2.0
	var prevTm time.Time
	for version := 2; version <= 4; version++ {
		tm, err := TimeV(host, uint8(version))
		if err != nil {
			t.Errorf("[%s] v%d request failed: %s", host, version, err)
		}

		t.Logf("[%s] Current time (v%d): %v", host, version, tm)

		if version > 2 && tm.Sub(prevTm).Seconds() > timeout.Seconds()+delta {
			t.Errorf("[%s] Diff between v%d and v%d > %f seconds",
				host, version-1, version, delta)
		}
		prevTm = tm

		time.Sleep(time.Second) // Delay one second to prevent spam
	}
}

func TestStratum(t *testing.T) {
	timeout = 60 * time.Second

	for version := 2; version <= 4; version++ {
		r, err := Query(host, uint8(version))
		if err != nil {
			t.Errorf("[%s] v%d request failed: %s", host, version, err)
		}

		// pool.ntp.org servers should almost certainly have stratum 10 or less.
		if r.Stratum < 1 || r.Stratum > 10 {
			t.Errorf("[%s] Invalid stratum received: %d", host, r.Stratum)
		}

		time.Sleep(time.Second) // Delay one second to prevent spam
	}
}
