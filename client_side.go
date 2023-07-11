package proxyproto

import (
	"bytes"
	"errors"
	"math"
	"net"
	"strconv"
)

var (
	v1LocalValue = []byte("PROXY UNKNOWN\r\n")
	v2LocalValue = []byte("\r\n\r\n\x00\r\nQUIT\n\x20\x00\x00\x00")
)

var (
	ErrUnknownVersion      = errors.New("formater unknown version")
	ErrUnknownAddrFamily   = errors.New("formater unknown address family")
	ErrUnknownTranProtocol = errors.New("formater unknown transport protocol")
	ErrInvalidAddress      = errors.New("formater invalid source or destination address")
	ErrExceedPayloadLength = errors.New("payload's length exceeds uint16 (65535) when TLV will be wrote")
)

func formatHeader(h *Header, wantChecksum bool) ([]byte, error) {
	if h == nil {
		return nil, errors.New("header instance is nil")
	}
	if h.SrcAddr == nil || h.DstAddr == nil {
		return nil, errors.New("header is not found source and destination address")
	}

	if h.Version == Version1 {
		return formatV1(h)
	} else if h.Version == Version2 {
		return formatV2(h, wantChecksum)
	}
	return nil, ErrUnknownVersion
}

func formatV1(h *Header) ([]byte, error) {
	if h.Command == CMD_LOCAL {
		return v1LocalValue, nil
	}

	// version 1 supports tcp only.
	srcType, srcOK := h.SrcAddr.(*net.TCPAddr)
	dstType, dstOK := h.DstAddr.(*net.TCPAddr)
	if (!srcOK && !dstOK) || srcType == nil || dstType == nil {
		return nil, ErrInvalidAddress
	}
	h.TransportProtocol = SOCK_STREAM

	var buf bytes.Buffer
	buf.Write(v1Prefix)

	if len(srcType.IP.To4()) == net.IPv4len && len(dstType.IP.To4()) == net.IPv4len {
		buf.WriteString("TCP4 ")
		buf.WriteString(srcType.IP.To4().String())
		buf.WriteString(" ")
		buf.WriteString(dstType.IP.To4().String())
		buf.WriteString(" ")
		h.AddressFamily = AF_INET // IPv4
	} else if len(srcType.IP.To16()) == net.IPv6len && len(dstType.IP.To16()) == net.IPv6len {
		buf.WriteString("TCP6 ")
		buf.WriteString(srcType.IP.To16().String())
		buf.WriteString(" ")
		buf.WriteString(dstType.IP.To16().String())
		buf.WriteString(" ")
		h.AddressFamily = AF_INET6 // IPv6
	} else {
		return nil, ErrUnknownAddrFamily
	}

	buf.WriteString(strconv.Itoa(srcType.Port))
	buf.WriteString(" ")
	buf.WriteString(strconv.Itoa(dstType.Port))
	buf.WriteString("\r\n") // the CRLF sequence
	h.Raw = buf.Bytes()
	return h.Raw, nil
}

func formatV2(h *Header, wantChecksum bool) ([]byte, error) {
	if h.Command == CMD_LOCAL {
		return v2LocalValue, nil
	}

	var payloadBuf *bytes.Buffer
	var payloadLength uint16
	payloadBuf, payloadLength, h.AddressFamily, h.TransportProtocol = guessAndParseAddrs(h.SrcAddr, h.DstAddr)
	if payloadBuf == nil {
		return nil, ErrInvalidAddress
	}
	if uint16(payloadBuf.Len()) != payloadLength {
		return nil, ErrInvalidAddress
	}

	var verAndCmd = byte(Version2<<4) + 1                              // version 2, proxy command
	var afAndTp = byte(h.AddressFamily<<4) + byte(h.TransportProtocol) // address family and transport protocol

	if len(h.TLVs) == 0 && !wantChecksum {
		h.Raw = make([]byte, 0, 16+payloadLength)
		h.Raw = append(h.Raw, v2Signature...)
		h.Raw = append(h.Raw, verAndCmd, afAndTp, byte(payloadLength>>8), byte(payloadLength))
		h.Raw = append(h.Raw, payloadBuf.Bytes()...)
		return h.Raw, nil
	}

	for _, tlv := range h.TLVs {
		data := tlv.Format()
		if l := len(data); 3 < l && l < math.MaxUint16 {
			if payloadBuf.Len()+l > math.MaxUint16 {
				return nil, ErrExceedPayloadLength
			}
			payloadBuf.Write(data)
			payloadLength += uint16(l)
		}
	}

	var err error
	h.Raw, err = formatV2Bytes(verAndCmd, afAndTp, payloadLength, payloadBuf, wantChecksum)
	return h.Raw, err
}

func formatV2Bytes(verAndCmd, afAndTp byte, length uint16, payload *bytes.Buffer, wantChecksum bool) ([]byte, error) {
	if wantChecksum {
		// ensure payload length is valid
		if int(length)+7 > math.MaxUint16 {
			return nil, ErrExceedPayloadLength
		}
		length += 7 // CRC-32c TLV: 1+2+4=7 bytes
	}
	var appendNOOP bool
	if int(length)+11 < math.MaxUint16 {
		length += 11 // NOOP TLV: 1+2+8=11 bytes
		appendNOOP = true
	}

	var buf = make([]byte, 0, 16+length)
	buf = append(buf, v2Signature...)
	buf = append(buf, verAndCmd, afAndTp, byte(length>>8), byte(length))

	if wantChecksum {
		raw := make([]byte, 0, 16+length)
		raw = append(raw, buf...)
		raw = append(raw, payload.Bytes()...)
		raw = append(raw, byte(PP2_TYPE_CRC32C), 0, 4, 0, 0, 0, 0)
		if appendNOOP {
			noopTLV := NewNoOpTLV(8)
			raw = append(raw, noopTLV.Format()...)
		}

		checksumBytes := CalcCRC32cChecksum(raw)
		// write CRC-32c checksum in payload
		checksumTLV := NewTLV(PP2_TYPE_CRC32C, checksumBytes)
		payload.Write(checksumTLV.Format())
	}

	if appendNOOP {
		noopTLV := NewNoOpTLV(8)
		payload.Write(noopTLV.Format())
	}
	return append(buf, payload.Bytes()...), nil
}
