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
