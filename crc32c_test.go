package proxyproto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var checksumCRC32cRaw = []byte("\r\n\r\n\x00\r\nQUIT\n" + // v2 signature
	"\x21\x11\x00\x43" + // version 2, proxy command, IPv4, TCP, payload length of 67
	"\x7F\x00\x00\x01\x7F\x00\x00\x01" + // source and destination ips are 127.0.0.1
	"\x30\x39\xDD\xD5" + // source port is 12345, destination port is 56789
	"\xEA\x00\x22vcpe-abcdefg-hijklmn-opqrst-uvwxyz" + // type:234, length:34, value:vcpe-abcdefg-hijklmn-opqrst-uvwxyz
	"\x03\x00\x04\x13\x49\xCA\x53" + // type:PP2_TYPE_CRC32C, length:4, value:"\x13\x49\xCA\x53"
	"\x04\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00") // type:PP2_TYPE_NOOP, length:8, value:"\x00\x00\x00\x00\x00\x00\x00\x00"

var checksumCRC32cTests = []struct {
	name string
	h    *Header
	want bool
}{
	{
		name: "pass-v1",
		h:    &Header{Version: Version1},
		want: true,
	}, {
		name: "pass-local",
		h:    &Header{Version: Version2, Command: CMD_LOCAL},
		want: true,
	}, {
		name: "pass-unkown-transport-protocol",
		h:    &Header{Version: Version2, Command: CMD_PROXY},
		want: true,
	}, {
		name: "pass-unkown-address-family",
		h:    &Header{Version: Version2, Command: CMD_PROXY, TransportProtocol: SOCK_STREAM},
		want: true,
	}, {
		name: "pass-crc32c",
		h: &Header{
			Version:           Version2,
			Command:           CMD_PROXY,
			AddressFamily:     AF_INET,
			TransportProtocol: SOCK_STREAM,
			Raw:               checksumCRC32cRaw,
		},
		want: true,
	}, {
		name: "failure-crc32c",
		h: &Header{
			Version:           Version2,
			Command:           CMD_PROXY,
			AddressFamily:     AF_INET,
			TransportProtocol: SOCK_STREAM,
			Raw: func() []byte {
				tmp := make([]byte, len(checksumCRC32cRaw))
				copy(tmp, checksumCRC32cRaw)
				tmp[len(tmp)-1]++ // modify to bad
				return tmp
			}(),
		},
		want: false,
	},
}

func TestChecksumCRC32c(t *testing.T) {
	for _, tt := range checksumCRC32cTests {
		t.Run(tt.name, func(t *testing.T) {
			got := ChecksumCRC32c(tt.h)
			require.Equal(t, tt.want, got)
		})
	}
}
