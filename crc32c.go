package proxyproto

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
)

// crc32cTab CRC-32c table.
// CRC-32c uses a polynomial (0x1EDC6F41, reversed 0x82F63B78).
// This is also known as the Castagnoli CRC32 and which can compute a full 32-bit CRC step in 3 cycles.
var crc32cTab = crc32.MakeTable(crc32.Castagnoli)

var ErrValidateCRC32cChecksum = errors.New("pp2 failed to validate CRC-32c checksum")

// ChecksumCRC32c CRC-32c checksum with header.
// just do it when the header is valid and contains a CRC-32c checksum.
func ChecksumCRC32c(h *Header) bool {
	// does not meet the conditions for verification
	if h == nil || h.Command != CMD_PROXY || h.Version != Version2 || h.TransportProtocol.String() == Unknown {
		return true
	}

	// offset is a starting position of the TLV groups.
	// 12 + 1 + 1 + 2 = 16 bytes.
	var offset = 16
	switch h.AddressFamily {
	case AF_INET:
		offset += addressLengthIPv4
	case AF_INET6:
		offset += addressLengthIPv6
	case AF_UNIX:
		offset += addressLengthUnix
	default:
		// reject unknown address family
		return true
	}

	// TLV flow
	var length = len(h.Raw)
	for offset < length {
		t := PP2Type(h.Raw[offset])
		// move byte over type
		offset++

		// break if offset is overflow
		if offset+2 > length {
			break
		}
		l := int(binary.BigEndian.Uint16(h.Raw[offset : offset+2]))
		// move bytes over length
		offset += 2

		// check crc-32c checksum
		if t == PP2_TYPE_CRC32C {
			// return if offset is overflow
			if offset+4 > length {
				return true
			}
			// due to idempotent
			var val = make([]byte, length)
			copy(val, h.Raw)
			// convert to crc-32c checksum
			recvCRC32cChecksum := binary.BigEndian.Uint32(val[offset : offset+4])
			//replace the 32 bits of the checksum field in the received PROXY header with all '0's.
			copy(val[offset:offset+4], []byte{0, 0, 0, 0})
			// calculate a CRC32c checksum value of the whole PROXY header.
			calcCRC32cChecksum := crc32.Checksum(val, crc32cTab)
			// verify that the calculated CRC32c checksum is the same as the received CRC32c checksum.
			return recvCRC32cChecksum == calcCRC32cChecksum
		}

		// move bytes over values
		offset += l
	}

	// does not meet the conditions for verification, because of
	// the checksum is not provided as part of the PROXY header.
	return true
}
