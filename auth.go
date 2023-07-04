package ntp

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
)

// AuthType specifies the cryptographic hash algorithm used to generate an
// authentication digest. Although multiple cryptographic algorithms are
// theoretically supported by well-known NTP servers, in practice only MD5 and
// SHA1 are commonly used.
type AuthType int

const (
	AuthNone AuthType = iota // no authentication used
	AuthMD5
	AuthSHA1
)

// AuthOptions contains fields necessary to configure a symmetrically
// authenticated NTP request.
type AuthOptions struct {
	Type  AuthType // cryptographic algorithm used to compute the digest
	Key   string   // key (hex-encoded if longer than 20 characters, ASCII if 20 or less)
	KeyID uint16   // key identifier
}

const ntpHeaderSize = 48

func appendMAC(buf *bytes.Buffer, opt AuthOptions, key []byte) {
	header := buf.Bytes()
	digest := calcDigest(opt.Type, header, key)
	binary.Write(buf, binary.BigEndian, uint32(opt.KeyID))
	binary.Write(buf, binary.BigEndian, digest)
}

func verifyMAC(buf []byte, opt AuthOptions, key []byte) error {
	macLen := 24
	if opt.Type == AuthMD5 {
		macLen = 20
	}

	// Validate that there are enough bytes at the end of the message to
	// contain a MAC.
	remain := len(buf) - ntpHeaderSize
	if remain < macLen || (remain%4) != 0 {
		return ErrAuthFailed
	}

	// The key ID returned by the server must be the same as the key ID sent
	// to the server.
	headerLen := len(buf) - macLen
	mac := buf[headerLen:]
	keyID := binary.BigEndian.Uint32(mac[:4])
	if keyID != uint32(opt.KeyID) {
		return ErrAuthFailed
	}

	// Calculate and compare digests.
	header := buf[:headerLen]
	digest := calcDigest(opt.Type, header, key)
	if subtle.ConstantTimeCompare(digest, mac[4:]) != 1 {
		return ErrAuthFailed
	}

	return nil
}

func calcDigest(authType AuthType, header, key []byte) []byte {
	data := append(key, header...)
	switch authType {
	case AuthMD5:
		digest := md5.Sum(data)
		return digest[:]
	case AuthSHA1:
		digest := sha1.Sum(data)
		return digest[:]
	}
	return nil // unreachable code
}

func decodeAuthKey(opt AuthOptions) ([]byte, error) {
	switch {
	case len(opt.Key) == 0:
		return nil, ErrInvalidAuthKey
	case len(opt.Key) > 20:
		key, err := hex.DecodeString(opt.Key)
		if err != nil {
			return nil, ErrInvalidAuthKey
		}
		return key, nil
	default:
		return []byte(opt.Key), nil
	}
}
