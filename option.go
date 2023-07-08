package proxyproto

import "time"

type Option func(*Conn)

// WithReadHeaderTimeout read header with timeout
func WithReadHeaderTimeout(duration time.Duration) Option {
	return func(c *Conn) {
		c.readHeaderTimeout = duration
	}
}

// WithDisableProxyProto header is not read
func WithDisableProxyProto(disable bool) Option {
	return func(c *Conn) {
		c.disableProxyProtocol = disable
	}
}

// WithPostReadHeader want to do after reading header, such as logging
func WithPostReadHeader(fn PostReadHeader) Option {
	return func(c *Conn) {
		c.postFunc = fn
	}
}

// WithCRC32cChecksum validate CRC-32c checksum.
// pp2 (proxy protocol version 2) will validate it.
func WithCRC32cChecksum(want bool) Option {
	return func(c *Conn) {
		c.checksum = want
	}
}
