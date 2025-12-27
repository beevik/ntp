// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ntp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
