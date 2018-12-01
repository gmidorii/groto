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
const user = "user"
const password = "password"

func accept(conn net.Conn) {
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

	if !groto.InitApproval(b) {
		i, err := groto.NewProtoInit(groto.NG)
		if err != nil {
			log.Println("[ERROR] failed create init proto")
			return
		}
		_, err = conn.Write(i.Build())
		if err != nil {
			log.Println("[ERROR] failed write")
			return
		}

		log.Println("[ERROR] connection first byte must be 0x05")
		return
	}
	log.Println("OK Connection")

	i, err := groto.NewProtoInit(groto.OK)
	if err != nil {
		log.Println("[ERROR] failed create init proto")
		return
	}
	conn.Write(i.Build())

	_, err = conn.Read(b)
	if err != nil {
		log.Println("[ERROR] failed read connection")
		return
	}

	c, err := groto.ParseConfirm(b)
	if err != nil {
		log.Printf("[ERROR] failed parse confirm packet: %v", err)
		return
	}
	u := make([]byte, 10)
	copy(u, []byte(user))
	p := groto.HashPw(i.PwHash(), []byte(password))

	if !c.Confirm(i.Id(), u, p[:]) {
		r := groto.NewProtoConfirmResult(c.Id(), groto.NG)
		_, err = conn.Write(r.Build())
		if err != nil {
			return
		}
		return
	}
	r := groto.NewProtoConfirmResult(c.Id(), groto.OK)
	_, err = conn.Write(r.Build())
	if err != nil {
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
