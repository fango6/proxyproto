package proxyproto

import (
	"bytes"
	"math"
	"net"
	"strconv"

	"github.com/pkg/errors"
)

func parseAndValidateIP(srcIpStr, dstIpStr string, af AddressFamily) (net.IP, net.IP, error) {
	var srcIP = net.ParseIP(srcIpStr)
	if err := validateIP(srcIP, af); err != nil {
		return nil, nil, errors.Wrap(err, "source IP")
	}

	var dstIP = net.ParseIP(dstIpStr)
	if err := validateIP(dstIP, af); err != nil {
		return nil, nil, errors.Wrap(err, "destination IP")
	}
	return srcIP, dstIP, nil
}

func validateIP(ip net.IP, af AddressFamily) error {
	if ip == nil {
		return errors.New("invalid or empty IP")
	}
	if af == AF_INET && ip.To4() == nil {
		return errors.New("invalid IPv4")
	}
	if af == AF_INET6 && ip.To16() == nil {
		return errors.New("invalid IPv6")
	}
	return nil
}

func parseAndValidatePort(srcPortStr, dstPortStr string) (int, int, error) {
	srcPort, err := strconv.Atoi(srcPortStr)
	if err != nil {
		return 0, 0, errors.Wrap(err, "source port")
	}
	if err := validatePort(srcPort); err != nil {
		return 0, 0, errors.Wrap(err, "source port")
	}

	dstPort, err := strconv.Atoi(dstPortStr)
	if err != nil {
		return 0, 0, errors.Wrap(err, "destination port")
	}
	if err := validatePort(dstPort); err != nil {
		return 0, 0, errors.Wrap(err, "destination port")
	}
	return srcPort, dstPort, nil
}

func validatePort(port int) error {
	if port <= 0 || port >= math.MaxUint16 {
		return errors.New("invalid port")
	}
	return nil
}

// guessAndParseAddrs guess the addresses what are type, and parse them.
func guessAndParseAddrs(srcAddr, dstAddr net.Addr) (*bytes.Buffer, uint16, AddressFamily, TransportProtocol) {
	var srcIP, dstIP net.IP
	var srcPort, dstPort int
	var tp TransportProtocol

	switch srcType := srcAddr.(type) {
	case *net.TCPAddr:
		dstType, ok := dstAddr.(*net.TCPAddr)
		if !ok {
			return nil, 0, 0, 0
		}
		srcIP, dstIP, srcPort, dstPort = srcType.IP, dstType.IP, srcType.Port, dstType.Port
		tp = SOCK_STREAM

	case *net.UDPAddr:
		dstType, ok := dstAddr.(*net.UDPAddr)
		if !ok {
			return nil, 0, 0, 0
		}
		srcIP, dstIP, srcPort, dstPort = srcType.IP, dstType.IP, srcType.Port, dstType.Port
		tp = SOCK_DGRAM

	case *net.UnixAddr:
		dstType, ok := dstAddr.(*net.UnixAddr)
		if !ok {
			return nil, 0, 0, 0
		}
		if srcType.Net == "unix" {
			tp = SOCK_STREAM
		} else if srcType.Net == "unixgram" {
			tp = SOCK_DGRAM
		}
		var payloadBuf = bytes.NewBuffer([]byte(formatUnixName(srcType.Name) + formatUnixName(dstType.Name)))
		return payloadBuf, addressLengthUnix, AF_UNIX, tp
	}

	if len(srcIP) == 0 || len(dstIP) == 0 || validatePort(srcPort) != nil || validatePort(dstPort) != nil {
		return nil, 0, 0, 0
	}

	var payloadBuf = &bytes.Buffer{}
	if len(srcIP.To4()) == net.IPv4len && len(dstIP.To4()) == net.IPv4len {
		payloadBuf.Write(srcIP.To4())
		payloadBuf.Write(dstIP.To4())
		payloadBuf.Write([]byte{byte(srcPort >> 8), byte(srcPort), byte(dstPort >> 8), byte(dstPort)})
		return payloadBuf, addressLengthIPv4, AF_INET, tp
	} else if len(srcIP.To16()) == net.IPv6len && len(dstIP.To16()) == net.IPv6len {
		payloadBuf.Write(srcIP.To16())
		payloadBuf.Write(dstIP.To16())
		payloadBuf.Write([]byte{byte(srcPort >> 8), byte(srcPort), byte(dstPort >> 8), byte(dstPort)})
		return payloadBuf, addressLengthIPv6, AF_INET6, tp
	}
	return nil, 0, 0, 0
}

func validatePayloadLength(length uint16, af AddressFamily) error {
	switch af {
	case AF_INET:
		if length < addressLengthIPv4 {
			return ErrPayloadLengthTooShort
		}
	case AF_INET6:
		if length < addressLengthIPv6 {
			return ErrPayloadLengthTooShort
		}
	case AF_UNIX:
		if length < addressLengthUnix {
			return ErrPayloadLengthTooShort
		}
	}
	return nil
}

func parseUnixName(name []byte) string {
	i := bytes.IndexByte(name, 0)
	if i < 0 {
		return string(name)
	}
	return string(name[:i])
}

func formatUnixName(name string) string {
	half := addressLengthUnix / 2
	if len(name) >= half {
		return name[:half]
	}

	filler := make([]byte, half-len(name))
	return name + string(filler)
}
