package proxyproto

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var readAndParseV1Tests = []struct {
	name string
	raw  string
	want *Header
}{
	{
		name: "tcp4",
		raw:  "PROXY TCP4 127.0.0.1 127.0.0.1 12345 56789\r\n",
		want: &Header{
			Version:           Version1,
			Command:           CMD_PROXY,
			AddressFamily:     AF_INET,
			TransportProtocol: SOCK_STREAM,
			SrcAddr:           &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
			DstAddr:           &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 56789},
			Raw:               []byte("PROXY TCP4 127.0.0.1 127.0.0.1 12345 56789\r\n"),
		},
	}, {
		name: "tcp6",
		raw:  "PROXY TCP6 1:2:3:4:5:6:7:8 1:2:3:4:5:6:7:8 12345 56789\r\n",
		want: &Header{
			Version:           Version1,
			Command:           CMD_PROXY,
			AddressFamily:     AF_INET6,
			TransportProtocol: SOCK_STREAM,
			SrcAddr:           &net.TCPAddr{IP: net.ParseIP("1:2:3:4:5:6:7:8"), Port: 12345},
			DstAddr:           &net.TCPAddr{IP: net.ParseIP("1:2:3:4:5:6:7:8"), Port: 56789},
			Raw:               []byte("PROXY TCP6 1:2:3:4:5:6:7:8 1:2:3:4:5:6:7:8 12345 56789\r\n"),
		},
	}, {
		name: "unknown",
		raw:  "PROXY UNKNOWN\r\n",
		want: &Header{
			Version:           Version1,
			Command:           CMD_LOCAL,
			AddressFamily:     AF_UNSPEC,
			TransportProtocol: SOCK_UNSPEC,
			Raw:               []byte("PROXY UNKNOWN\r\n"),
		},
	},
}

// Test_readAndParseV1 want success
func Test_readAndParseV1(t *testing.T) {
	for _, tt := range readAndParseV1Tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(tt.raw))
			got, err := readAndParseV1(reader)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// Test_readV1 want error
func Test_readV1(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr error
	}{
		{
			name:    "prefix-not-present",
			raw:     "PROXY",
			wantErr: ErrNoProxyProtocol,
		}, {
			name:    "fake-ppv1-header",
			raw:     "PROXY ",
			wantErr: io.EOF,
		}, {
			name:    "early-EOF",
			raw:     "PROXY TCP4 127.0.0.1 127.0.0.1 12345 56789",
			wantErr: io.EOF,
		}, {
			name:    "must-end-with-crlf",
			raw:     "PROXY TCP4 127.0.0.1 127.0.0.1 12345 56789\n",
			wantErr: ErrMustEndWithCRLF,
		}, {
			name:    "too-long",
			raw:     "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 12345 56789 xx\r\n",
			wantErr: ErrHeaderTooLong,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(tt.raw))
			_, err := readV1(reader)
			require.Error(t, err)
			require.EqualError(t, err, tt.wantErr.Error())
		})
	}
}

// Test_parseV1 want error
func Test_parseV1(t *testing.T) {
	tests := []struct {
		name    string
		raw     []byte
		wantErr error
	}{
		{
			name:    "not-found-address-family",
			raw:     []byte("PROXY \r\n"),
			wantErr: ErrNotFoundAddressFamily,
		}, {
			name:    "invalid-address-family",
			raw:     []byte("PROXY UNIX\r\n"),
			wantErr: ErrInvalidAddressFamily,
		}, {
			name:    "not-found-address-ports",
			raw:     []byte("PROXY TCP4\r\n"),
			wantErr: ErrNotFoundAddressOrPort,
		}, {
			name:    "not-found-dest-address-ports",
			raw:     []byte("PROXY TCP4 127.0.0.1\r\n"),
			wantErr: ErrNotFoundAddressOrPort,
		}, {
			name:    "not-found-ports",
			raw:     []byte("PROXY TCP4 127.0.0.1 127.0.0.1\r\n"),
			wantErr: ErrNotFoundAddressOrPort,
		}, {
			name:    "not-found-dest-port",
			raw:     []byte("PROXY TCP4 127.0.0.1 127.0.0.1 12345\r\n"),
			wantErr: ErrNotFoundAddressOrPort,
		}, {
			name:    "invalid-source-ip",
			raw:     []byte("PROXY TCP4 256.0.0.1 127.0.0.1 12345 56789\r\n"),
			wantErr: errors.New("source IP: invalid or empty IP"),
		}, {
			name:    "invalid-destination-port",
			raw:     []byte("PROXY TCP4 127.0.0.1 127.0.0.1 12345 67890\r\n"),
			wantErr: errors.New("destination port: invalid port"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseV1(tt.raw)
			require.Error(t, err)
			require.EqualError(t, err, tt.wantErr.Error())
		})
	}
}
