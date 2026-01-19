// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ntp

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// The NTP server to use for online unit tests. May be overridden by the
// NTP_HOST environment variable.
var host string = "0.beevik-ntp.pool.ntp.org"

const (
	refID      = 0xc0a80001
	timeFormat = "Mon Jan _2 2006  15:04:05.00000000 (MST)"
)

func init() {
	h := os.Getenv("NTP_HOST")
	if h != "" {
		host = h
	}
}

func fmtKissCode(s string) string {
	if s == "" {
		return "<empty>"
	}
	return s
}

func fmtLeapIndicator(li LeapIndicator) string {
	switch li {
	case LeapNoWarning:
		return "No Warning"
	case LeapAddSecond:
		return "Add Second"
	case LeapDelSecond:
		return "Delete Second"
	default:
		return "Unknown"
	}
}

func fmtResponseFlags(flags ResponseFlags) string {
	ftab := map[ResponseFlags]string{
		FlagSynchronized: "Synchronized",
		FlagInterleaved:  "Interleaved",
	}

	copy := flags
	var s strings.Builder
	s.WriteString("[")
	for flags != 0 {
		f := flags & -flags
		if s.Len() > 1 {
			s.WriteString(" ")
		}
		if ss, ok := ftab[f]; ok {
			s.WriteString(ss)
		} else {
			s.WriteString("Unknown")
		}
		flags &= ^f
	}
	fmt.Fprintf(&s, "] (0x%08x)", uint32(copy))
	return s.String()
}

func fmtTime(value time.Time) string {
	if value.IsZero() {
		return "<zero>"
	}
	return value.Format(timeFormat)
}

func fmtTimescale(ts Timescale) string {
	switch ts {
	case TimescaleUTC:
		return "UTC"
	case TimescaleTAI:
		return "TAI"
	case TimescaleUT1:
		return "UT1"
	case TimescaleUTCSmeared:
		return "UTC(smeared)"
	default:
		return "Unknown"
	}
}

func isError(t *testing.T, host string, err error) bool {
	switch {
	case err == nil:
		return false
	case err == ErrKissOfDeath:
		// log instead of error, so test isn't failed
		t.Logf("[%s] Query kiss of death (ignored)", host)
		return true
	case strings.Contains(err.Error(), "timeout"):
		// log instead of error, so test isn't failed
		t.Logf("[%s] Query timeout (ignored): %s", host, err)
		return true
	default:
		// error, so test fails
		t.Errorf("[%s] Query failed: %s", host, err)
		return true
	}
}

func assertValid(t *testing.T, r *Response) {
	err := r.Validate()
	_ = isError(t, host, err)
}

func assertInvalid(t *testing.T, r *Response) {
	err := r.Validate()
	if err == nil {
		t.Errorf("[%s] Response unexpectedly valid\n", host)
	}
}

func TestOfflineFixHostPort(t *testing.T) {
	const defaultPort = 123

	cases := []struct {
		address string
		fixed   string
		errMsg  string
	}{
		{"192.168.1.1", "192.168.1.1:123", ""},
		{"192.168.1.1:123", "192.168.1.1:123", ""},
		{"192.168.1.1:1000", "192.168.1.1:1000", ""},
		{"[192.168.1.1]:1000", "[192.168.1.1]:1000", ""},
		{"www.example.com", "www.example.com:123", ""},
		{"www.example.com:123", "www.example.com:123", ""},
		{"www.example.com:1000", "www.example.com:1000", ""},
		{"[www.example.com]:1000", "[www.example.com]:1000", ""},
		{"::1", "[::1]:123", ""},
		{"[::1]", "[::1]:123", ""},
		{"[::1]:123", "[::1]:123", ""},
		{"[::1]:1000", "[::1]:1000", ""},
		{"fe80::1", "[fe80::1]:123", ""},
		{"[fe80::1]", "[fe80::1]:123", ""},
		{"[fe80::1]:123", "[fe80::1]:123", ""},
		{"[fe80::1]:1000", "[fe80::1]:1000", ""},
		{"[fe80::", "", "missing ']' in address"},
		{"[fe80::]@", "", "unexpected character following ']' in address"},
		{"ff06:0:0:0:0:0:0:c3", "[ff06:0:0:0:0:0:0:c3]:123", ""},
		{"[ff06:0:0:0:0:0:0:c3]", "[ff06:0:0:0:0:0:0:c3]:123", ""},
		{"[ff06:0:0:0:0:0:0:c3]:123", "[ff06:0:0:0:0:0:0:c3]:123", ""},
		{"[ff06:0:0:0:0:0:0:c3]:1000", "[ff06:0:0:0:0:0:0:c3]:1000", ""},
		{"::ffff:192.168.1.1", "[::ffff:192.168.1.1]:123", ""},
		{"[::ffff:192.168.1.1]", "[::ffff:192.168.1.1]:123", ""},
		{"[::ffff:192.168.1.1]:123", "[::ffff:192.168.1.1]:123", ""},
		{"[::ffff:192.168.1.1]:1000", "[::ffff:192.168.1.1]:1000", ""},
		{"", "", "address string is empty"},
	}
	for _, c := range cases {
		fixed, err := fixHostPort(c.address, defaultPort)
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		assert.Equal(t, c.fixed, fixed)
		assert.Equal(t, c.errMsg, errMsg)
	}
}

func TestOfflineMeasurements(t *testing.T) {
	const format = "5.000000"
	base := time.Date(2026, 0, 0, 0, 0, 0, 0, time.UTC)

	cases := []struct {
		t1, t2, t3, t4 time.Time
		offset         time.Duration
		rtt            time.Duration
		minError       time.Duration
	}{
		{
			base,
			base.Add(1 * time.Millisecond),
			base.Add(1 * time.Millisecond),
			base.Add(1 * time.Millisecond),
			500 * time.Microsecond,
			1 * time.Millisecond,
			0,
		},
		{
			base,
			base.Add(1 * time.Millisecond),
			base.Add(1 * time.Millisecond),
			base.Add(10 * time.Millisecond),
			-4 * time.Millisecond,
			10 * time.Millisecond,
			0,
		},
		{
			base,
			base.Add(1 * time.Millisecond),
			base.Add(1 * time.Millisecond),
			base.Add(25 * time.Microsecond),
			987*time.Microsecond + 500*time.Nanosecond,
			25 * time.Microsecond,
			975 * time.Microsecond,
		},
		{
			base,
			base.Add(1 * time.Millisecond),
			base.Add(1 * time.Millisecond),
			base.Add(2 * time.Microsecond),
			999 * time.Microsecond,
			2 * time.Microsecond,
			998 * time.Microsecond,
		},
		{
			base,
			base.Add(25 * time.Millisecond),
			base.Add(25 * time.Millisecond),
			base.Add(1 * time.Millisecond),
			24*time.Millisecond + 500*time.Microsecond,
			1 * time.Millisecond,
			24 * time.Millisecond,
		},
		{
			base.Add(78 * time.Millisecond),
			base.Add(38 * time.Millisecond),
			base.Add(38 * time.Millisecond),
			base.Add(94 * time.Millisecond),
			-48 * time.Millisecond,
			16 * time.Millisecond,
			40 * time.Millisecond,
		},
		{
			base.Add(78 * time.Millisecond),
			base.Add(38 * time.Millisecond),
			base.Add(39 * time.Millisecond),
			base.Add(94 * time.Millisecond),
			-47*time.Millisecond - 500*time.Microsecond,
			15 * time.Millisecond,
			40 * time.Millisecond,
		},
		{
			base.Add(78 * time.Millisecond),
			base.Add(38 * time.Millisecond),
			base.Add(39 * time.Millisecond),
			base.Add(95 * time.Millisecond),
			-48 * time.Millisecond,
			16 * time.Millisecond,
			40 * time.Millisecond,
		},
		{
			base.Add(18 * time.Millisecond),
			base.Add(38 * time.Millisecond),
			base.Add(39 * time.Millisecond),
			base.Add(35 * time.Millisecond),
			12 * time.Millisecond,
			16 * time.Millisecond,
			4 * time.Millisecond,
		},
		{
			base.Add(10 * time.Millisecond),
			base.Add(30 * time.Millisecond),
			base.Add(30 * time.Millisecond),
			base.Add(30 * time.Millisecond),
			10 * time.Millisecond,
			20 * time.Millisecond,
			0,
		},
		{
			base.Add(10 * time.Millisecond),
			base.Add(30 * time.Millisecond),
			base.Add(30 * time.Millisecond),
			base.Add(20 * time.Millisecond),
			15 * time.Millisecond,
			10 * time.Millisecond,
			10 * time.Millisecond,
		},
		{
			base.Add(10 * time.Millisecond),
			base.Add(30 * time.Millisecond),
			base.Add(30 * time.Millisecond),
			base.Add(40 * time.Millisecond),
			5 * time.Millisecond,
			30 * time.Millisecond,
			0,
		},
		{
			base.Add(10 * time.Millisecond),
			base.Add(30 * time.Millisecond),
			base.Add(32 * time.Millisecond),
			base.Add(40 * time.Millisecond),
			6 * time.Millisecond,
			28 * time.Millisecond,
			0,
		},
	}

	for _, c := range cases {
		offset := offset(c.t1, c.t2, c.t3, c.t4)
		if offset != c.offset {
			t.Errorf("offset(%s, %s, %s, %s) = %s; want %s",
				c.t1.Format(format),
				c.t2.Format(format),
				c.t3.Format(format),
				c.t4.Format(format),
				offset, c.offset)
		}

		rtt := rtt(c.t1, c.t2, c.t3, c.t4)
		if rtt != c.rtt {
			t.Errorf("minError(%s, %s, %s, %s) = %s; want %s",
				c.t1.Format(format),
				c.t2.Format(format),
				c.t3.Format(format),
				c.t4.Format(format),
				rtt, c.rtt)
		}

		m := minError(c.t1, c.t2, c.t3, c.t4)
		if m != c.minError {
			t.Errorf("minError(%s, %s, %s, %s) = %s; want %s",
				c.t1.Format(format),
				c.t2.Format(format),
				c.t3.Format(format),
				c.t4.Format(format),
				m, c.minError)
		}
	}
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
		{0x4e54534e, "NTSN"},
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
