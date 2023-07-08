package proxyproto

import (
	"net"
	"time"
)

const (
	defaultReadHeaderTimeout = time.Second * 5
)

type Listener struct {
	net.Listener

	options []Option
}

func NewListener(listener net.Listener, opts ...Option) *Listener {
	return &Listener{
		Listener: listener,
		options:  opts,
	}
}

func (ln *Listener) Accept() (net.Conn, error) {
	rawConn, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}

	conn := NewConn(rawConn, ln.options...)
	if conn.readHeaderTimeout <= 0 {
		conn.readHeaderTimeout = defaultReadHeaderTimeout
	}
	return conn, nil
}

func (ln *Listener) Close() error {
	return ln.Listener.Close()
}

func (ln *Listener) Addr() net.Addr {
	return ln.Listener.Addr()
}
