package main

import (
	"fmt"
	"log"
	"net"
	"os"
)

const dPort = "3030"

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

		go func() {
			defer func() {
				log.Println("Close")
				conn.Close()
			}()
			log.Printf("Accept: %v", conn.RemoteAddr())

			b := make([]byte, 2*1024)
			_, err := conn.Read(b)
			if err != nil {
				log.Println("[ERROR] failed read connection")
				return
			}
			if b[0] != 0x05 {
				log.Println("[ERROR] connection first byte must be 0x05")
				return
			}
			log.Println("OK Connection")

			for {
				b := make([]byte, 2*1024)
				_, err := conn.Read(b)
				if err != nil {
					log.Println("[ERROR] failed read content connection")
					return
				}

				fmt.Printf("%b\n", b)
				fmt.Printf("%X\n", b)
				fmt.Printf("%v\n", string(b))
			}
		}()
	}
}

func main() {
	if err := listen(); err != nil {
		log.Fatalf("listen error %v", err)
	}
}
