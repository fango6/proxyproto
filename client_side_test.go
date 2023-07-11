package proxyproto

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_formatV1(t *testing.T) {
	tests := []struct {
		name string
		h    *Header
		want []byte
	}{
		{
			name: "local",
			h:    &Header{Version: Version1, Command: CMD_LOCAL},
			want: []byte("PROXY UNKNOWN\r\n"),
		}, {
			name: "proxy-tcp-ipv4",
			h: &Header{
				Version: Version1,
				Command: CMD_PROXY,
				SrcAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
				DstAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 56789},
			},
			want: []byte("PROXY TCP4 127.0.0.1 127.0.0.1 12345 56789\r\n"),
		}, {
			name: "proxy-tcp-ipv6",
			h: &Header{
				Version: Version1,
				Command: CMD_PROXY,
				SrcAddr: &net.TCPAddr{IP: net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), Port: 12345},
				DstAddr: &net.TCPAddr{IP: net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), Port: 56789},
			},
			want: []byte("PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 12345 56789\r\n"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := formatV1(tt.h)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func Test_formatV2(t *testing.T) {
	tests := []struct {
		name         string
		h            *Header
		wantChecksum bool
		want         []byte
	}{
		{
			name: "local",
			h:    &Header{Version: Version2, Command: CMD_LOCAL},
			want: []byte("\r\n\r\n\x00\r\nQUIT\n\x20\x00\x00\x00"),
		}, {
			name: "proxy-tcp-ipv4",
			h: &Header{
				Version: Version2,
				Command: CMD_PROXY,
				SrcAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
				DstAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 56789},
			},
			want: []byte("\r\n\r\n\x00\r\nQUIT\n" +
				"\x21\x11\x00\x0C" +
				"\x7F\x00\x00\x01" +
				"\x7F\x00\x00\x01" +
				"\x30\x39\xDD\xD5"),
		}, {
			name: "proxy-tcp-ipv4-checksum",
			h: &Header{
				Version: Version2,
				Command: CMD_PROXY,
				SrcAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
				DstAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 56789},
			},
			wantChecksum: true,
			want: []byte("\r\n\r\n\x00\r\nQUIT\n" +
				"\x21\x11\x00\x1E" +
				"\x7F\x00\x00\x01" +
				"\x7F\x00\x00\x01" +
				"\x30\x39\xDD\xD5" +
				"\x03\x00\x04\xBF\xFF\x0E\xAA" +
				"\x04\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00"),
		}, {
			name: "proxy-tcp-ipv4-tlv",
			h: &Header{
				Version: Version2,
				Command: CMD_PROXY,
				SrcAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
				DstAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 56789},
				TLVs:    TLVs{NewTLV(PP2Type(234), []byte("vcpe-abcdefg-hijklmn-opqrst-uvwxyz"))},
			},
			want: []byte("\r\n\r\n\x00\r\nQUIT\n" +
				"\x21\x11\x00\x3C" +
				"\x7F\x00\x00\x01\x7F\x00\x00\x01\x30\x39\xDD\xD5" +
				"\xEA\x00\x22vcpe-abcdefg-hijklmn-opqrst-uvwxyz" +
				"\x04\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00"),
		}, {
			name: "proxy-tcp-ipv4-tlv-checksum",
			h: &Header{
				Version: Version2,
				Command: CMD_PROXY,
				SrcAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
				DstAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 56789},
				TLVs:    TLVs{NewTLV(PP2Type(234), []byte("vcpe-abcdefg-hijklmn-opqrst-uvwxyz"))},
			},
			wantChecksum: true,
			want: []byte("\r\n\r\n\x00\r\nQUIT\n" +
				"\x21\x11\x00\x43" +
				"\x7F\x00\x00\x01\x7F\x00\x00\x01\x30\x39\xDD\xD5" +
				"\xEA\x00\x22vcpe-abcdefg-hijklmn-opqrst-uvwxyz" +
				"\x03\x00\x04\x13\x49\xCA\x53" +
				"\x04\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := formatV2(tt.h, tt.wantChecksum)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
