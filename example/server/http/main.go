package main

import (
	"log"
	"net"
	"net/http"

	"github.com/fango6/proxyproto"
)

var addr = "127.0.0.1:9090"

func main() {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}

	proxyListener := proxyproto.NewListener(ln)

	srv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Println("recv request url:", r.URL.Path)
		}),
	}

	err = srv.Serve(proxyListener)
	log.Println(err)
}
