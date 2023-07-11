package proxyproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// PP2Type type of proxy protocol version 2
type PP2Type byte

// The following types have already been registered for the <type> field:
const (
	PP2_TYPE_ALPN           PP2Type = 0x01
	PP2_TYPE_AUTHORITY      PP2Type = 0x02
	PP2_TYPE_CRC32C         PP2Type = 0x03
	PP2_TYPE_NOOP           PP2Type = 0x04
	PP2_TYPE_UNIQUE_ID      PP2Type = 0x05
	PP2_TYPE_SSL            PP2Type = 0x20
	PP2_SUBTYPE_SSL_VERSION PP2Type = 0x21
	PP2_SUBTYPE_SSL_CN      PP2Type = 0x22
	PP2_SUBTYPE_SSL_CIPHER  PP2Type = 0x23
	PP2_SUBTYPE_SSL_SIG_ALG PP2Type = 0x24
	PP2_SUBTYPE_SSL_KEY_ALG PP2Type = 0x25
	PP2_TYPE_NETNS          PP2Type = 0x30
)

// TLV a Type-Length-Value group
type TLV struct {
	Type   PP2Type
	Length uint16
	Value  []byte
}

// TLVs TLV groups
type TLVs []TLV

var (
	ErrTlvLenTooShort = errors.New("TLV's length is too short")
	ErrTlvValTooShort = errors.New("TLV's values are too short")
)

func parseTLVs(rawTLVs []byte) (TLVs, error) {
	var tlvs TLVs
	var rawLen = len(rawTLVs)

	for cursor := 0; cursor < rawLen; {
		pp2Type := PP2Type(rawTLVs[cursor])
		cursor++
		if cursor+2 > rawLen {
			return nil, ErrTlvLenTooShort
		}

		length := int(binary.BigEndian.Uint16(rawTLVs[cursor : cursor+2]))
		cursor += 2
		if cursor+length > rawLen {
			return nil, ErrTlvValTooShort
		}

		value := make([]byte, length)
		copy(value, rawTLVs[cursor:cursor+length])
		cursor += length

		tlvs = append(tlvs, TLV{Type: pp2Type, Length: uint16(length), Value: value})
	}
	return tlvs, nil
}

func NewTLV(t PP2Type, val []byte) TLV {
	return TLV{
		Type:   t,
		Length: uint16(len(val)),
		Value:  val,
	}
}

// NewNoOpTLV create a PP2_TYPE_NOOP TLV group.
func NewNoOpTLV(length uint16) TLV {
	return TLV{
		Type:   PP2_TYPE_NOOP,
		Length: length,
		Value:  make([]byte, length),
	}
}

// Format format to raw bytes for PROXY sender.
func (tlv TLV) Format() []byte {
	l := len(tlv.Value)
	// not values
	if l == 0 {
		// no-op
		if tlv.Type == PP2_TYPE_NOOP && tlv.Length > 0 {
			return make([]byte, tlv.Length)
		}
		return nil
	}

	var buf = make([]byte, 0, l)
	buf = append(buf, byte(tlv.Type), byte(l>>8), byte(l))
	buf = append(buf, tlv.Value...)
	return buf
}

// IsRegistered true if type have already been registered
func (tlv TLV) IsRegistered() bool {
	switch tlv.Type {
	case PP2_TYPE_ALPN,
		PP2_TYPE_AUTHORITY,
		PP2_TYPE_CRC32C,
		PP2_TYPE_NOOP,
		PP2_TYPE_UNIQUE_ID,
		PP2_TYPE_SSL,
		PP2_SUBTYPE_SSL_VERSION,
		PP2_SUBTYPE_SSL_CN,
		PP2_SUBTYPE_SSL_CIPHER,
		PP2_SUBTYPE_SSL_SIG_ALG,
		PP2_SUBTYPE_SSL_KEY_ALG,
		PP2_TYPE_NETNS:

		return true
	}
	return false
}

func (tlv TLV) String() string {
	return fmt.Sprintf("[type:%d,length:%d,value:%q]", tlv.Type, tlv.Length, tlv.Value)
}

func (s TLVs) String() string {
	if len(s) == 0 {
		return ""
	}

	var fields []string
	for _, tlv := range s {
		// skip display
		if tlv.IsRegistered() {
			continue
		}
		fields = append(fields, tlv.String())
	}
	return strings.Join(fields, ",")
}
