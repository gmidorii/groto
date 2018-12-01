package main

import (
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

	cli := groto.NewClient(user, password)
	if err := cli.Do(conn); err != nil {
		return err
	}

	// implementation

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
