package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/midorigreen/groto"
)

const dPort = "3030"

func accept(conn net.Conn) {
	defer func() {
		log.Println("Close")
		conn.Close()
	}()
	log.Printf("Accept: %v", conn.RemoteAddr())

	s := groto.NewServer()
	if err := s.Do(conn); err != nil {
		return
	}

	for {
		b := make([]byte, 2*1024)
		_, err := conn.Read(b)
		if err != nil {
			if err == io.EOF {
				return
			}

			log.Println("[ERROR] failed read content connection")
			return
		}

		fmt.Printf("%b\n", b)
		fmt.Printf("%X\n", b)
		fmt.Printf("%v\n", string(b))
	}
}

func listen() error {
	port := dPort
	if ep := os.Getenv("PORT"); ep != "" {
		port = ep
	}

	l, err := net.Listen("tcp", fmt.Sprintf(":%v", port))
	if err != nil {
		return err
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println(err)
		}
		go accept(conn)
	}
}

func main() {
	if err := listen(); err != nil {
		log.Fatalf("listen error %v", err)
	}
}
