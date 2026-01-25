// Copyright © Brett Vickers.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ntp

import (
	"encoding/binary"
	"unsafe"
)

// nativeEndian is the byte order for the current system architecture.
var nativeEndian binary.ByteOrder

func init() {
	// Infer native endianness by storing and reading back a multi-byte value.
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xabcd)

	switch buf {
	case [2]byte{0xcd, 0xab}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xab, 0xcd}:
		nativeEndian = binary.BigEndian
	default:
		panic("could not determine native endianness")
	}
}
