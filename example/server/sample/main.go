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
