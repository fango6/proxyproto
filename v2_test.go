package proxyproto

import (
	"bufio"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var readAndParseV2Tests = []struct {
	name string
	raw  string
	want *Header
}{
	{
		name: "local-command",
		raw: ("\r\n\r\n\x00\r\nQUIT\n" + // version 2 signature
			"\x20" + // version 2, local command
			"\x11" + // IPv4, TCP
			"\x00\x00"), // payload length of zero
		want: &Header{
			Version:           Version2,
			Command:           CMD_LOCAL,
			AddressFamily:     AF_INET,
			TransportProtocol: SOCK_STREAM,
		},
	}, {
		name: "proxy-command-IPv4",
		raw: ("\r\n\r\n\x00\r\nQUIT\n" + // version 2 signature
			"\x21\x11\x00\x0C" + // version 2, proxy command, IPv4, TCP, payload length of 12
			"\x7F\x00\x00\x01" + // source ip is 127.0.0.1
			"\x7F\x00\x00\x01" + // destination ip is 127.0.0.1
			"\x30\x39\xDD\xD5"), // source port is 12345, destination port is 56789
		want: &Header{
			Version:           Version2,
			Command:           CMD_PROXY,
			AddressFamily:     AF_INET,
			TransportProtocol: SOCK_STREAM,
			SrcAddr:           &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
			DstAddr:           &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 56789},
		},
	}, {
		name: "proxy-command-IPv6",
		raw: ("\r\n\r\n\x00\r\nQUIT\n" + // version 2 signature
			"\x21\x21\x00\x24" + // version 2, proxy command, IPv6, TCP, payload length of 36
			"\x00\x7F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" + // source ip is 127:0:0:0:0:0:0:1
			"\x00\x7F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" + // destination ip is 127:0:0:0:0:0:0:1
			"\x30\x39\xDD\xD5"), // source port is 12345, destination port is 56789
		want: &Header{
			Version:           Version2,
			Command:           CMD_PROXY,
			AddressFamily:     AF_INET6,
			TransportProtocol: SOCK_STREAM,
			SrcAddr: &net.TCPAddr{
				IP:   net.IP([]byte("\x00\x7F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")),
				Port: 12345,
			},
			DstAddr: &net.TCPAddr{
				IP:   net.IP([]byte("\x00\x7F\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")),
				Port: 56789,
			},
		},
	}, {
		name: "tlv-groups",
		raw: ("\r\n\r\n\x00\r\nQUIT\n" + // version 2 signature
			"\x21\x11\x00\x3C" + // version 2, proxy command, IPv4, TCP, payload length of 60
			"\x7F\x00\x00\x01\x7F\x00\x00\x01" + // source and destination ips are 127.0.0.1
			"\x30\x39\xDD\xD5" + // source port is 12345, destination port is 56789
			"\xEA\x00\x22vcpe-abcdefg-hijklmn-opqrst-uvwxyz" + // type:234, length:34, value:vcpe-abcdefg-hijklmn-opqrst-uvwxyz
			"\x04\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00"), // type:PP2_TYPE_NOOP, length:8, value:"\x00\x00\x00\x00\x00\x00\x00\x00"
		want: &Header{
			Version:           Version2,
			Command:           CMD_PROXY,
			AddressFamily:     AF_INET,
			TransportProtocol: SOCK_STREAM,
			SrcAddr:           &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
			DstAddr:           &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 56789},
			TLVs: TLVs{
				{Type: 234, Length: 34, Value: []byte("vcpe-abcdefg-hijklmn-opqrst-uvwxyz")},
				{Type: 4, Length: 8, Value: []byte("\x00\x00\x00\x00\x00\x00\x00\x00")},
			},
		},
	}, {
		name: "tlv-crc32c-group",
		raw: ("\r\n\r\n\x00\r\nQUIT\n" + // v2 signature
			"\x21\x11\x00\x43" + // version 2, proxy command, IPv4, TCP, payload length of 67
			"\x7F\x00\x00\x01\x7F\x00\x00\x01" + // source and destination ips are 127.0.0.1
			"\x30\x39\xDD\xD5" + // source port is 12345, destination port is 56789
			"\xEA\x00\x22vcpe-abcdefg-hijklmn-opqrst-uvwxyz" + // type:234, length:34, value:vcpe-abcdefg-hijklmn-opqrst-uvwxyz
			"\x03\x00\x04\x13\x49\xCA\x53" + // type:PP2_TYPE_CRC32C, length:4, value:"\x13\x49\xCA\x53"
			"\x04\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00"), // type:PP2_TYPE_NOOP, length:8, value:"\x00\x00\x00\x00\x00\x00\x00\x00"
		want: &Header{
			Version:           Version2,
			Command:           CMD_PROXY,
			AddressFamily:     AF_INET,
			TransportProtocol: SOCK_STREAM,
			SrcAddr:           &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
			DstAddr:           &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 56789},
			TLVs: TLVs{
				{Type: 234, Length: 34, Value: []byte("vcpe-abcdefg-hijklmn-opqrst-uvwxyz")},
				{Type: 3, Length: 4, Value: []byte("\x13\x49\xCA\x53")},
				{Type: 4, Length: 8, Value: []byte("\x00\x00\x00\x00\x00\x00\x00\x00")},
			},
		},
	},
}

// Test_readAndParseV2 want success
func Test_readAndParseV2(t *testing.T) {
	for _, tt := range readAndParseV2Tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.want.Raw = []byte(tt.raw)
			reader := bufio.NewReader(strings.NewReader(tt.raw))
			got, err := readAndParseV2(reader)

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}

	t.Run("proxy-command-Unix", func(t *testing.T) {
		dir, err := os.MkdirTemp("", "")
		require.NoError(t, err)

		t.Cleanup(func() {
			err := os.RemoveAll(dir)
			require.NoError(t, err)
		})

		var namePrefix = filepath.Join(dir, "sock")
		var nameSuffix = make([]byte, addressLengthUnix/2-len(namePrefix))
		var name = namePrefix + string(nameSuffix)
		var raw = "\r\n\r\n\x00\r\nQUIT\n" + // version signature
			"\x21\x31\x00\xD8" + // version 2, proxy, tcp, 216
			name + name

		var want = &Header{
			Version:           Version2,
			Command:           CMD_PROXY,
			AddressFamily:     AF_UNIX,
			TransportProtocol: SOCK_STREAM,
			SrcAddr:           &net.UnixAddr{Name: namePrefix, Net: "unix"},
			DstAddr:           &net.UnixAddr{Name: namePrefix, Net: "unix"},
			Raw:               []byte(raw),
		}
		gotHeader, err := readAndParseV2(bufio.NewReader(strings.NewReader(raw)))
		require.NoError(t, err)
		require.Equal(t, want, gotHeader)
	})
}

var readV2Tests = []struct {
	name    string
	raw     string
	wantErr error
}{
	{
		name:    "not pp2 header",
		raw:     "\t\n\r\n\x00\r\nQUIT\t",
		wantErr: ErrNoProxyProtocol,
	}, {
		name:    "invalid version",
		raw:     "\r\n\r\n\x00\r\nQUIT\n" + "\x51",
		wantErr: ErrUnknownVersionAndCommand,
	}, {
		name:    "unknown command",
		raw:     "\r\n\r\n\x00\r\nQUIT\n" + "\x25",
		wantErr: ErrUnknownVersionAndCommand,
	}, {
		name:    "unknown address family",
		raw:     "\r\n\r\n\x00\r\nQUIT\n" + "\x21\x51",
		wantErr: ErrUnknownAddrFamilyAndTranProtocol,
	}, {
		name:    "unknown transport protocol",
		raw:     "\r\n\r\n\x00\r\nQUIT\n" + "\x21\x15",
		wantErr: ErrUnknownAddrFamilyAndTranProtocol,
	}, {
		name:    "payload length is unexpected",
		raw:     "\r\n\r\n\x00\r\nQUIT\n" + "\x21\x11\x01",
		wantErr: io.ErrUnexpectedEOF,
	}, {
		name:    "payload is missing",
		raw:     "\r\n\r\n\x00\r\nQUIT\n" + "\x21\x11\x00\x0F",
		wantErr: io.EOF,
	}, {
		name:    "payload length invalid",
		raw:     "\r\n\r\n\x00\r\nQUIT\n" + "\x21\x11\x00\x0A",
		wantErr: ErrPayloadLengthTooShort,
	}, {
		name: "payload too short",
		raw: ("\r\n\r\n\x00\r\nQUIT\n" +
			"\x21\x11\x00\x0C" +
			"\x7F\x00\x00\x01\x7F\x00\x00\x01\x04\xD2"),
		wantErr: ErrPayloadBytesTooShort,
	},
}

func Test_readV2(t *testing.T) {
	for _, tt := range readV2Tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReader(strings.NewReader(tt.raw))
			_, err := readV2(reader)
			require.EqualError(t, err, tt.wantErr.Error())
		})
	}
}

func Test_parseV2(t *testing.T) {
	t.Run("payload is empty", func(t *testing.T) {
		header := &Header{
			Version:           Version2,
			Command:           CMD_PROXY,
			AddressFamily:     AF_INET,
			TransportProtocol: SOCK_STREAM,
			Raw:               []byte("\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x0C"),
		}
		err := parseV2(header)
		require.EqualError(t, err, "pp2 payload is empty")
	})
	t.Run("unknown address family", func(t *testing.T) {
		header := &Header{
			Version:           Version2,
			Command:           CMD_PROXY,
			AddressFamily:     AF_UNSPEC,
			TransportProtocol: SOCK_STREAM,
			Raw: []byte("\r\n\r\n\x00\r\nQUIT\n\x21\x01\x00\x0C" +
				"\x7F\x00\x00\x01\x7F\x00\x00\x01\x30\x39\xDD\xD5"),
		}
		err := parseV2(header)
		require.EqualError(t, err, ErrUnknownAddrFamilyAndTranProtocol.Error())
	})
}
