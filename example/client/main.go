package main

import (
	"log"
	"net"
	"time"

	"github.com/fango6/proxyproto"
)

func main() {
	h := &proxyproto.Header{
		Version:           proxyproto.Version2,
		Command:           proxyproto.CMD_PROXY,
		AddressFamily:     proxyproto.AF_INET,
		TransportProtocol: proxyproto.SOCK_STREAM,

		SrcAddr: &net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 12345,
		},
		DstAddr: &net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 56789,
		},
	}

	raw, err := h.FormatWithChecksum()
	if err != nil {
		log.Println("err:", err)
		return
	}

	conn, err := net.DialTimeout("tcp", "127.0.0.1:9090", time.Second*5)
	if err != nil {
		log.Println("err:", err)
		return
	}
	n, err := h.WriteTo(conn)
	if err != nil || n != len(raw) {
		log.Println("write PROXY header to connection fail:", err)
	}
}
