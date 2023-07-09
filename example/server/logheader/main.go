package main

import (
	"log"
	"net"

	"github.com/fango6/proxyproto"
	"github.com/sirupsen/logrus"
)

func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:9090")
	if err != nil {
		log.Fatal(err)
	}

	proxyListener := proxyproto.NewListener(ln, proxyproto.WithPostReadHeader(loggingHeader))
	for {
		conn, err := proxyListener.Accept()
		if err != nil {
			log.Println(err)
			continue
		}

		go serve(conn)
	}
}

func serve(tcpConn net.Conn) {
	// do something
	conn, ok := tcpConn.(*proxyproto.Conn)
	if ok && conn != nil {
		// do something
	}
}

func loggingHeader(h *proxyproto.Header, err error) {
	if err != nil {
		logrus.WithError(err).Error("failed to parse proxy header")
		return
	}
	logrus.WithFields(h.LogrusFields()).Info("successfully parsed proxy header")
}
