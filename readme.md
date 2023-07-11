# proxyproto

Go language to imeplementation of PROXY Protocol.

Supports version 1 & 2, TLV and CRC-32c (PP2_TYPE_CRC32C).

The official documentation: [https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt](https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt)


## Usage

### Server Side

```go
package main

import (
	"log"
	"net"

	"github.com/fango6/proxyproto"
)

func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:9090")
	if err != nil {
		log.Fatal(err)
	}

	proxyListener := proxyproto.NewListener(ln)
	for {
		conn, err := proxyListener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		go server(conn)
	}
}

func server(conn net.Conn) {
	// do something
}

```

### Client Side

```go
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

	raw, err := h.Format()
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

```

More usages in the example folder, please move to there.
