package main

import (
	"flag"
	"fmt"
	"log"
	"net"
)

func request(address string, port int) error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%v:%v", address, port))
	if err != nil {
		return err
	}
	defer conn.Close()

	conn.Write([]byte{0x05})
	conn.Write([]byte("hogehoge"))

	return nil
}

func main() {
	a := flag.String("a", "localhost", "connection address")
	p := flag.Int("p", 3030, "port")
	flag.Parse()

	if err := request(*a, *p); err != nil {
		log.Fatalln(err)
	}
}
