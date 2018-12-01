package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/midorigreen/groto"
)

func request(port int, address, user, password string) error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%v:%v", address, port))
	if err != nil {
		return err
	}
	defer conn.Close()

	// init
	_, err = conn.Write([]byte{0x05})
	if err != nil {
		return err
	}

	// init result
	b := make([]byte, 34)
	_, err = conn.Read(b)
	if err != nil {
		return err
	}
	i, err := groto.ParseInit(b)
	if err != nil {
		return err
	}
	if !i.IsOk() {
		return errors.New("failed init")
	}
	log.Println("OK Handshake")

	hPw := groto.HashPw(i.PwHash(), []byte(password))
	c := groto.NewProtoConfirm(i.Id(), []byte(user), hPw)
	_, err = conn.Write(c.Build())
	if err != nil {
		return err
	}

	b = make([]byte, 10)
	_, err = conn.Read(b)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	p := flag.Int("p", 3030, "port")
	a := flag.String("a", "localhost", "connection address")
	u := flag.String("u", "user", "user name")
	pw := flag.String("pw", "password", "password")
	flag.Parse()

	if err := request(*p, *a, *u, *pw); err != nil {
		log.Fatalln(err)
	}
}
