package proxyproto

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"

	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
)

type (
	Version           byte // Version 1 or 2
	Command           byte // Local or Proxy
	AddressFamily     byte // IPv4, IPv6 or Unix
	TransportProtocol byte // TCP or UDP
)

type Header struct {
	Version           Version
	Command           Command
	AddressFamily     AddressFamily
	TransportProtocol TransportProtocol

	SrcAddr net.Addr // source address
	DstAddr net.Addr // destination address

	Raw  []byte // raw proxy protocol header
	TLVs TLVs   // all of TLV groups
}

const (
	Version1 Version = 0x1 // Version 1
	Version2 Version = 0x2 // Version 2

	CMD_LOCAL Command = 0x0 // Local
	CMD_PROXY Command = 0x1 // Proxy

	AF_UNSPEC AddressFamily = 0x0 // Unspec
	AF_INET   AddressFamily = 0x1 // IPv4
	AF_INET6  AddressFamily = 0x2 // IPv6
	AF_UNIX   AddressFamily = 0x3 // Unix

	SOCK_UNSPEC TransportProtocol = 0x0 // Unspec
	SOCK_STREAM TransportProtocol = 0x1 // TCP
	SOCK_DGRAM  TransportProtocol = 0x2 // UDP

	Unknown string = "Unknown" // Unknown value
)

var (
	v1Prefix = []byte("PROXY ")
	// v2 signature: \x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A
	v2Signature = []byte("\r\n\r\n\x00\r\nQUIT\n")

	ErrNoProxyProtocol = errors.New("proxy protocol prefix not present")
)

func ReadHeader(reader *bufio.Reader) (*Header, error) {
	prefix, err := reader.Peek(len(v1Prefix))
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ErrNoProxyProtocol
		}
		return nil, err
	}

	if bytes.Equal(prefix, v1Prefix) {
		return readAndParseV1(reader)
	} else if !bytes.HasPrefix(v2Signature, prefix) {
		return nil, ErrNoProxyProtocol
	}

	prefix, err = reader.Peek(len(v2Signature))
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ErrNoProxyProtocol
		}
		return nil, err
	}

	if bytes.Equal(prefix, v2Signature) {
		return readAndParseV2(reader)
	}
	return nil, ErrNoProxyProtocol
}

// Format format header to bytes.
func (h *Header) Format() ([]byte, error) {
	return formatHeader(h, false)
}

// FormatWithChecksum formater header to bytes, and append checksum with CRC-32c.
func (h *Header) FormatWithChecksum() ([]byte, error) {
	return formatHeader(h, true)
}

// WriteTo implements io.WriteTo
func (h *Header) WriteTo(w io.Writer) (int, error) {
	return w.Write(h.Raw)
}

func (h *Header) ZapFields() []zap.Field {
	var srcAddr, dstAddr string
	if h.SrcAddr != nil {
		srcAddr = h.SrcAddr.String()
	}
	if h.DstAddr != nil {
		dstAddr = h.DstAddr.String()
	}

	fields := make([]zap.Field, 0, 7)
	fields = append(fields,
		zap.String("version", h.Version.String()),
		zap.String("command", h.Command.String()),
		zap.String("address_family", h.AddressFamily.String()),
		zap.String("transport_protocol", h.TransportProtocol.String()),
		zap.String("source_address", srcAddr),
		zap.String("destination_address", dstAddr),
	)
	if h.Version == Version2 && h.Command == CMD_PROXY && len(h.TLVs) > 0 {
		fields = append(fields, zap.String("tlv_groups", h.TLVs.String()))
	}
	return fields
}

func (h *Header) LogrusFields() logrus.Fields {
	var srcAddr, dstAddr string
	if h.SrcAddr != nil {
		srcAddr = h.SrcAddr.String()
	}
	if h.DstAddr != nil {
		dstAddr = h.DstAddr.String()
	}

	fields := make(logrus.Fields, 7)
	fields["version"] = h.Version.String()
	fields["command"] = h.Command.String()
	fields["address_family"] = h.AddressFamily.String()
	fields["transport_protocol"] = h.TransportProtocol.String()
	fields["source_address"] = srcAddr
	fields["destination_address"] = dstAddr
	if h.Version == Version2 && h.Command == CMD_PROXY && len(h.TLVs) > 0 {
		fields["tlv_groups"] = h.TLVs.String()
	}
	return fields
}

func (v Version) String() string {
	switch v {
	case Version1:
		return "V1"
	case Version2:
		return "V2"
	}
	return Unknown
}

func (c Command) String() string {
	switch c {
	case CMD_LOCAL:
		return "V1"
	case CMD_PROXY:
		return "V2"
	}
	return Unknown
}

func (af AddressFamily) String() string {
	switch af {
	case AF_INET:
		return "IPv4"
	case AF_INET6:
		return "IPv4"
	case AF_UNIX:
		return "Unix"
	}
	return Unknown
}

func (tp TransportProtocol) String() string {
	switch tp {
	case SOCK_STREAM:
		return "TCP"
	case SOCK_DGRAM:
		return "UDP"
	}
	return Unknown
}
