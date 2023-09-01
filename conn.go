package proxyproto

import (
	"bufio"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
)

// PostReadHeader will be called after reading Proxy Protocol header.
type PostReadHeader func(h *Header, err error)

// Conn wrap net.Conn, want to read and parse Proxy Protocol header, and so on.
type Conn struct {
	net.Conn

	reader *bufio.Reader

	Header            *Header
	readHeaderOnce    sync.Once     // ensure to read header only once
	readHeaderTimeout time.Duration // maximum time spent reading header
	originalDeadline  time.Time     // use to reset deadline after reading header
	readHeaderErr     error

	disableProxyProtocol bool // true if disable proxy protocol
	checksum             bool // true if check CRC-32c checksum
	postFunc             PostReadHeader
}

func NewConn(conn net.Conn, opts ...Option) *Conn {
	c := &Conn{
		Conn:   conn,
		reader: bufio.NewReader(conn),
	}

	for _, o := range opts {
		o(c)
	}
	return c
}

// Read implement net.Conn, in order to read Proxy Protocol header
func (c *Conn) Read(b []byte) (int, error) {
	c.readHeader()
	return c.Conn.Read(b)
}

// LocalAddr implement net.Conn, in order to read Proxy Protocol header
func (c *Conn) LocalAddr() net.Addr {
	c.readHeader()
	if c.Header != nil && c.Header.Command != CMD_LOCAL && c.Header.DstAddr != nil && c.readHeaderErr == nil {
		return c.Header.DstAddr
	}
	return c.Conn.LocalAddr()
}

// RemoteAddr implement net.Conn, in order to read Proxy Protocol header
func (c *Conn) RemoteAddr() net.Addr {
	c.readHeader()
	if c.Header != nil && c.Header.Command != CMD_LOCAL && c.Header.SrcAddr != nil && c.readHeaderErr != nil {
		return c.Header.SrcAddr
	}
	return c.Conn.RemoteAddr()
}

// SetDeadline implement net.Conn, in order to catch deadline
func (c *Conn) SetDeadline(t time.Time) error {
	c.originalDeadline = t
	return c.Conn.SetDeadline(t)
}

// SetReadDeadline implement net.Conn, in order to catch deadline
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.originalDeadline = t
	return c.Conn.SetReadDeadline(t)
}

// TLVs get TLVs of pp2
func (c *Conn) TLVs() TLVs {
	if c.Header == nil {
		return nil
	}
	return c.Header.TLVs
}

// GetVpceID find VPC endpoint ID in the PROXY header's TLVs.
// an unregistered PP2Type will be choosen, and the first byte discarded.
func (c *Conn) GetVpceID() string {
	if c.Header == nil || len(c.Header.TLVs) == 0 {
		return ""
	}
	for _, tlv := range c.Header.TLVs {
		if !tlv.IsRegistered() {
			return string(tlv.Value[1:])
		}
	}
	return ""
}

// GetVpceIDWithType gets VPC endpoint ID with PP2Type from PROXY header.
// the subtype of 0 returns all values, otherwise the first byte is discarded.
func (c *Conn) GetVpceIDWithType(typ PP2Type, subType PP2Type) string {
	if c.Header == nil || len(c.Header.TLVs) == 0 {
		return ""
	}
	for _, tlv := range c.Header.TLVs {
		if tlv.Type == typ {
			if subType == 0 {
				return string(tlv.Value)
			}
			return string(tlv.Value[1:])
		}
	}
	return ""
}

// RawHeader get raw header
func (c *Conn) RawHeader() []byte {
	if c.Header == nil {
		return nil
	}
	return c.Header.Raw
}

// Err read header error
func (c *Conn) Err() error {
	return c.readHeaderErr
}

// ZapFields header fields for zap
func (c *Conn) ZapFields() []zap.Field {
	if c.Header == nil {
		return nil
	}
	return c.Header.ZapFields()
}

// LogrusFields header fields for logrus
func (c *Conn) LogrusFields() logrus.Fields {
	if c.Header == nil {
		return nil
	}
	return c.Header.LogrusFields()
}

// readHeader reader header of proxy protocol only once
func (c *Conn) readHeader() {
	c.readHeaderOnce.Do(func() {
		if c.disableProxyProtocol {
			return
		}

		originalDeadline := c.originalDeadline
		c.SetReadDeadline(time.Now().Add(c.readHeaderTimeout))
		defer c.SetReadDeadline(originalDeadline)

		reader := bufio.NewReader(c.Conn)
		header, err := ReadHeader(reader)

		if c.postFunc != nil {
			c.postFunc(header, err)
		}

		if err == nil && header != nil {
			// validate CRC-32c checksum
			if c.checksum && !ChecksumCRC32c(header) {
				c.readHeaderErr = ErrValidateCRC32cChecksum
				return
			}
			c.Header = header
			return
		}

		// it is not pp1 and pp2 header, ignore.
		if errors.Is(err, ErrNoProxyProtocol) {
			return
		}
		c.readHeaderErr = err
	})
}
