package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"

	"github.com/pkg/errors"
)

const (
	// addressLengthIPv4 address length is 2*4 + 2*2 = 12 bytes.
	addressLengthIPv4 = 12
	// addressLengthIPv6 address length is 2*16 + 2*2 = 36 bytes.
	addressLengthIPv6 = 36
	// addressLengthUnix address length is 2*108 = 216 bytes.
	addressLengthUnix = 216
)

var (
	ErrUnknownVersionAndCommand         = errors.New("pp2 unknown version and command")
	ErrUnknownAddrFamilyAndTranProtocol = errors.New("pp2 unknown address family and transport protocol")
	ErrPayloadLengthTooShort            = errors.New("pp2 payload length is too short")
	ErrPayloadBytesTooShort             = errors.New("pp2 payload of bytes are too short")
)

// readAndParseV2 read and parse header of version 2.
func readAndParseV2(reader *bufio.Reader) (*Header, error) {
	header, err := readV2(reader)
	if err != nil {
		return nil, err
	}

	if err := parseV2(header); err != nil {
		return nil, err
	}
	return header, nil
}

// readV2 read header of version 2.
func readV2(reader *bufio.Reader) (*Header, error) {
	if reader == nil {
		return nil, errors.New("pp2 reader is nil")
	}

	var raw = make([]byte, len(v2Signature), len(v2Signature)+4)
	n, err := reader.Read(raw[:len(v2Signature)])
	if err != nil || n < len(v2Signature) || !bytes.Equal(raw, v2Signature) {
		return nil, ErrNoProxyProtocol
	}

	// 13th byte: version and command
	verAndCmd, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	ver, cmd := Version(verAndCmd>>4), Command(verAndCmd&0x0F)
	// reject all of unknown versions and commands
	if ver != Version2 || cmd.String() == Unknown {
		return nil, ErrUnknownVersionAndCommand
	}

	// 14th byte: address family and transport protocol
	afAndTp, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	af, tp := AddressFamily(afAndTp>>4), TransportProtocol(afAndTp&0x0F)
	// reject all of unknown address family, and transport protocols
	if af.String() == Unknown || tp.String() == Unknown {
		return nil, ErrUnknownAddrFamilyAndTranProtocol
	}

	// 15~16th bytes: number of following bytes part of the header
	var payloadLength uint16
	if err := binary.Read(io.LimitReader(reader, 2), binary.BigEndian, &payloadLength); err != nil {
		return nil, err
	}

	raw = append(raw, verAndCmd, afAndTp, byte(payloadLength>>8), byte(payloadLength))
	header := &Header{Version: Version2, Command: cmd, AddressFamily: af, TransportProtocol: tp, Raw: raw}
	// command Local
	if payloadLength == 0 || header.Command == CMD_LOCAL {
		header.Command = CMD_LOCAL
		return header, nil
	}
	if err := validatePayloadLength(payloadLength, af); err != nil {
		return nil, err
	}

	var payload = make([]byte, payloadLength)
	n, err = reader.Read(payload)
	if err != nil {
		return nil, err
	}
	if n != int(payloadLength) {
		return nil, ErrPayloadBytesTooShort
	}

	header.Raw = make([]byte, 0, len(v2Signature)+4+int(payloadLength))
	header.Raw = append(header.Raw, raw...)
	header.Raw = append(header.Raw, payload...)
	return header, nil
}

// parseV2 parse header with Header
func parseV2(header *Header) error {
	if header == nil {
		return errors.New("pp2 header is nil")
	}
	if header.Command == CMD_LOCAL {
		return nil
	}
	if len(header.Raw) <= len(v2Signature)+4 {
		return errors.New("pp2 payload is empty")
	}

	var payload = header.Raw[len(v2Signature)+4:]
	var err error
	var srcAddr, dstAddr net.Addr
	var rawTLVs []byte

	switch header.AddressFamily {
	case AF_INET: // IPv4
		srcAddr, dstAddr, err = parseV2IPv4(payload, header.TransportProtocol)
		if err != nil {
			return err
		}
		rawTLVs = payload[addressLengthIPv4:]

	case AF_INET6: // IPv6
		srcAddr, dstAddr, err = parseV2IPv6(payload, header.TransportProtocol)
		if err != nil {
			return err
		}
		rawTLVs = payload[addressLengthIPv6:]

	case AF_UNIX: // Unix
		srcAddr, dstAddr, err = parseV2Unix(payload, header.TransportProtocol)
		if err != nil {
			return err
		}
		rawTLVs = payload[addressLengthUnix:]

	default:
		return ErrUnknownAddrFamilyAndTranProtocol
	}

	header.TLVs, err = parseTLVs(rawTLVs)
	if err != nil {
		return err
	}

	header.SrcAddr = srcAddr
	header.DstAddr = dstAddr
	return nil
}

func parseV2IPv4(payload []byte, tp TransportProtocol) (src, dst net.Addr, err error) {
	if len(payload) < addressLengthIPv4 {
		err = ErrPayloadBytesTooShort
		return
	}
	srcIP := net.IPv4(payload[0], payload[1], payload[2], payload[3])
	if err = validateIP(srcIP, AF_INET); err != nil {
		return nil, nil, errors.Wrap(err, "source")
	}

	dstIP := net.IPv4(payload[4], payload[5], payload[6], payload[7])
	if err = validateIP(dstIP, AF_INET); err != nil {
		return nil, nil, errors.Wrap(err, "destination")
	}

	srcPort := int(binary.BigEndian.Uint16(payload[8:10]))
	if err = validatePort(srcPort); err != nil {
		return nil, nil, errors.Wrap(err, "source")
	}

	dstPort := int(binary.BigEndian.Uint16(payload[10:addressLengthIPv4]))
	if err = validatePort(dstPort); err != nil {
		return nil, nil, errors.Wrap(err, "destination")
	}

	if tp == SOCK_DGRAM {
		src = &net.UDPAddr{IP: srcIP, Port: srcPort}
		dst = &net.UDPAddr{IP: dstIP, Port: dstPort}
		return
	}
	src = &net.TCPAddr{IP: srcIP, Port: srcPort}
	dst = &net.TCPAddr{IP: dstIP, Port: dstPort}
	return
}

func parseV2IPv6(payload []byte, tp TransportProtocol) (src, dst net.Addr, err error) {
	if len(payload) < addressLengthIPv6 {
		err = ErrPayloadBytesTooShort
		return
	}
	srcIP := net.IP(payload[:16])
	if err = validateIP(srcIP, AF_INET6); err != nil {
		return nil, nil, errors.Wrap(err, "source")
	}

	dstIP := net.IP(payload[16:32])
	if err = validateIP(dstIP, AF_INET6); err != nil {
		return nil, nil, errors.Wrap(err, "destination")
	}

	srcPort := int(binary.BigEndian.Uint16(payload[32:34]))
	if err = validatePort(srcPort); err != nil {
		return nil, nil, errors.Wrap(err, "source")
	}

	dstPort := int(binary.BigEndian.Uint16(payload[34:addressLengthIPv6]))
	if err = validatePort(dstPort); err != nil {
		return nil, nil, errors.Wrap(err, "destination")
	}

	if tp == SOCK_DGRAM {
		src = &net.UDPAddr{IP: srcIP, Port: srcPort}
		dst = &net.UDPAddr{IP: dstIP, Port: dstPort}
		return
	}
	src = &net.TCPAddr{IP: srcIP, Port: srcPort}
	dst = &net.TCPAddr{IP: dstIP, Port: dstPort}
	return
}

func parseV2Unix(payload []byte, tp TransportProtocol) (src, dst net.Addr, err error) {
	if len(payload) < addressLengthUnix {
		err = ErrPayloadBytesTooShort
		return
	}

	var network = "unix"
	if tp == SOCK_DGRAM {
		network = "unixgram"
	}

	src = &net.UnixAddr{Net: network, Name: parseUnixName(payload[:108])}
	dst = &net.UnixAddr{Net: network, Name: parseUnixName(payload[108:addressLengthUnix])}
	return
}
