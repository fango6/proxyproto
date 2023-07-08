package proxyproto

import (
	"bufio"
	"bytes"
	"net"
	"strings"

	"github.com/pkg/errors"
)

const (
	// worst case (optional fields set to 0xff):
	// "PROXY UNKNOWN ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n"
	// => 5 + 1 + 7 + 1 + 39 + 1 + 39 + 1 + 5 + 1 + 5 + 2 = 107 chars
	v1HeaderMaxLength = 107
)

var (
	ErrMustEndWithCRLF = errors.New("pp1 header must end with '\\r\\n'")
	ErrHeaderTooLong   = errors.New("pp1 header too long")

	ErrNotFoundAddressFamily = errors.New("pp1 header not found address family")
	ErrInvalidAddressFamily  = errors.New("pp1 invalid address family")
	ErrNotFoundAddressOrPort = errors.New("pp1 header not found address or port")
)

func readAndParseV1(reader *bufio.Reader) (*Header, error) {
	raw, err := readV1(reader)
	if err != nil {
		return nil, err
	}
	return parseV1(raw)
}

func readV1(reader *bufio.Reader) ([]byte, error) {
	if reader == nil {
		return nil, errors.New("pp1 reader is nil")
	}

	var raw = make([]byte, len(v1Prefix), v1HeaderMaxLength)
	// read v1 prefix
	n, err := reader.Read(raw[:len(v1Prefix)])
	if err != nil || n < len(v1Prefix) || !bytes.Equal(raw[:len(v1Prefix)], v1Prefix) {
		return nil, ErrNoProxyProtocol
	}

	for {
		b, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		// header the end
		if b == '\n' {
			// must end with the CRLF
			if pre := raw[len(raw)-1]; pre != '\r' {
				return nil, ErrMustEndWithCRLF
			}
			raw = append(raw, b)
			return raw, nil
		}

		raw = append(raw, b)
		if len(raw) >= v1HeaderMaxLength {
			return nil, ErrHeaderTooLong
		}
	}
}

func parseV1(raw []byte) (*Header, error) {
	fields := strings.Fields(string(bytes.TrimSpace(raw)))
	if len(fields) < 2 {
		return nil, ErrNotFoundAddressFamily
	}

	var af AddressFamily
	switch fields[1] {
	case "TCP4":
		af = AF_INET
	case "TCP6":
		af = AF_INET6
	case "UNKNOWN":
		af = AF_UNSPEC
	default:
		return nil, ErrInvalidAddressFamily
	}

	if af != AF_UNSPEC && len(fields) < 6 {
		return nil, ErrNotFoundAddressOrPort
	}

	header := &Header{Version: Version1, AddressFamily: af, Raw: raw}
	// set command to local, and return early
	if af != AF_INET && af != AF_INET6 {
		header.Command = CMD_LOCAL
		return header, nil
	}
	// just proxy by tcp
	header.Command = CMD_PROXY
	header.TransportProtocol = SOCK_STREAM

	srcIP, dstIP, err := parseAndValidateIP(fields[2], fields[3], af)
	if err != nil {
		return nil, err
	}

	sourcePort, destPort, err := parseAndValidatePort(fields[4], fields[5])
	if err != nil {
		return nil, err
	}
	header.SrcAddr = &net.TCPAddr{IP: srcIP, Port: sourcePort}
	header.DstAddr = &net.TCPAddr{IP: dstIP, Port: destPort}
	return header, nil
}
