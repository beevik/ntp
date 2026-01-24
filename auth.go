// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ntp

import (
	"crypto/aes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
)

// AuthType specifies the cryptographic hash algorithm used to generate a
// symmetric key authentication code for an NTP message. Please note that MD5
// and SHA1 are no longer considered secure and have been deprecated for use
// with NTP; they appear here solely for compatibility with older NTP server
// implementations. In general, the AES-128-CMAC algorithm should be used if
// the server supports it (see RFC 8573).
type AuthType int

const (
	AuthNone   AuthType = iota // no symmetric key authentication
	AuthMD5                    // MD5
	AuthSHA1                   // SHA-1
	AuthSHA256                 // SHA2-256
	AuthSHA512                 // SHA2-512
	AuthAES128                 // AES-128-CMAC
	AuthAES256                 // AES-256-CMAC
)

// AuthOptions contains fields used to configure symmetric key authentication
// for an NTP query.
type AuthOptions struct {
	// Type determines the cryptographic hash algorithm used to compute the
	// authentication code.
	Type AuthType

	// The cryptographic key used by the client to perform authentication. The
	// key may be hex-encoded or ascii-encoded. To use a hex-encoded key,
	// prefix it by "HEX:". To use an ascii-encoded key, prefix it by
	// "ASCII:". For example, "HEX:6931564b4a5a5045766c55356b30656c7666316c"
	// or "ASCII:cvuZyN4C8HX8hNcAWDWp".
	Key string

	// The identifier used by the NTP server to identify which key to use
	// for authentication purposes.
	KeyID uint32
}

var algorithms = []struct {
	MinKeySize int
	MaxKeySize int
	MACSize    int
	CalcMAC    func(payload, key []byte) []byte
}{
	{0, 0, 0, nil},               // AuthNone
	{4, 32, 16, calcDigest_MD5},  // AuthMD5
	{4, 32, 20, calcHash_SHA1},   // AuthSHA1
	{4, 32, 32, calcHash_SHA256}, // AuthSHA256
	{4, 32, 64, calcHash_SHA512}, // AuthSHA512
	{16, 16, 16, calcCMAC_AES},   // AuthAES128
	{32, 32, 16, calcCMAC_AES},   // AuthAES256
}

func calcDigest_MD5(payload, key []byte) []byte {
	digest := md5.Sum(append(key, payload...))
	return digest[:]
}

func calcHash_SHA1(payload, key []byte) []byte {
	hash := sha1.Sum(append(key, payload...))
	return hash[:]
}

func calcHash_SHA256(payload, key []byte) []byte {
	hash := sha256.Sum256(append(key, payload...))
	return hash[:]
}

func calcHash_SHA512(payload, key []byte) []byte {
	hash := sha512.Sum512(append(key, payload...))
	return hash[:]
}

func calcCMAC_AES(payload, key []byte) []byte {
	// calculate the CMAC according to the algorithm defined in RFC 4493. See
	// https://tools.ietf.org/html/rfc4493 for details.
	c, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Generate subkeys.
	const rb = 0x87
	k1 := make([]byte, 16)
	k2 := make([]byte, 16)
	c.Encrypt(k1, k1)
	double(k1, k1, rb)
	double(k2, k1, rb)

	// Process all but the last block.
	cmac := make([]byte, 16)
	for ; len(payload) > 16; payload = payload[16:] {
		xor(cmac, payload[:16])
		c.Encrypt(cmac, cmac)
	}

	// Process the last block, padding as necessary.
	if len(payload) == 16 {
		xor(cmac, payload)
		xor(cmac, k1)
	} else {
		xor(cmac, padblock(payload))
		xor(cmac, k2)
	}
	c.Encrypt(cmac, cmac)

	return cmac
}

func padblock(block []byte) []byte {
	pad := make([]byte, 16-len(block))
	pad[0] = 0x80
	return append(block, pad...)
}

func double(dst, src []byte, xor int) {
	_ = src[15] // compiler hint: bounds check
	s0 := binary.BigEndian.Uint64(src[0:8])
	s1 := binary.BigEndian.Uint64(src[8:16])

	carry := int(s0 >> 63)
	d0 := (s0 << 1) | (s1 >> 63)
	d1 := (s1 << 1) ^ uint64(subtle.ConstantTimeSelect(carry, xor, 0))

	_ = dst[15] // compiler hint: bounds check
	binary.BigEndian.PutUint64(dst[0:8], d0)
	binary.BigEndian.PutUint64(dst[8:16], d1)
}

func xor(dst, src []byte) {
	_ = src[15] // compiler hint: bounds check
	s0 := binary.BigEndian.Uint64(src[0:8])
	s1 := binary.BigEndian.Uint64(src[8:16])

	_ = dst[15] // compiler hint: bounds check
	d0 := s0 ^ binary.BigEndian.Uint64(dst[0:8])
	d1 := s1 ^ binary.BigEndian.Uint64(dst[8:16])

	binary.BigEndian.PutUint64(dst[0:8], d0)
	binary.BigEndian.PutUint64(dst[8:16], d1)
}

func decodeAuthKey(opt AuthOptions) (key []byte, err error) {
	var keyIn string
	var isHex bool
	switch {
	case len(opt.Key) >= 4 && opt.Key[:4] == "HEX:":
		isHex, keyIn = true, opt.Key[4:]
	case len(opt.Key) >= 6 && opt.Key[:6] == "ASCII:":
		isHex, keyIn = false, opt.Key[6:]
	case len(opt.Key) > 20:
		isHex, keyIn = true, opt.Key
	default:
		isHex, keyIn = false, opt.Key
	}

	if isHex {
		key, err = hex.DecodeString(keyIn)
		if err != nil {
			return nil, ErrInvalidAuthKey
		}
	} else {
		key = []byte(keyIn)
	}

	a := algorithms[opt.Type]
	if len(key) < a.MinKeySize {
		return nil, ErrInvalidAuthKey
	}
	if len(key) > a.MaxKeySize {
		key = key[:a.MaxKeySize]
	}

	return key, nil
}

func getMACSize(version int, authType AuthType) int {
	a := algorithms[authType]
	if version == 4 {
		// Truncate to 20 bytes for NTPv4.
		return min(a.MACSize, 20)
	}
	return a.MACSize
}

func calcMAC(version int, authType AuthType, key []byte, payload []byte) []byte {
	a := algorithms[authType]
	mac := a.CalcMAC(payload, key)
	size := getMACSize(version, authType)
	return mac[:size]
}
