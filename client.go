package groto

import (
	"errors"
	"log"
	"net"
)

type Client struct {
	user     string
	password string
	id       []byte
	hashKey  []byte
}

func NewClient(user, password string) *Client {
	return &Client{
		user:     user,
		password: password,
	}
}

func (c *Client) Do(conn net.Conn) error {
	if err := c.stepInit(conn); err != nil {
		return err
	}
	if err := c.stepConfirm(conn); err != nil {
		return err
	}
	return nil
}

func (c *Client) stepInit(conn net.Conn) error {
	_, err := conn.Write([]byte{byte(Init)})
	if err != nil {
		return err
	}

	b := make([]byte, initLen)
	_, err = conn.Read(b)
	if err != nil {
		return err
	}
	i, err := ParseInit(b)
	if err != nil {
		return err
	}
	if !i.IsOk() {
		return errors.New("failed init")
	}
	log.Println("OK Handshake")
	c.id = i.id
	c.hashKey = i.pwhash

	return nil
}

func (c *Client) stepConfirm(conn net.Conn) error {
	hPw := HashPw(c.hashKey, []byte(c.password))
	proto := NewProtoConfirm(c.id, []byte(c.user), hPw[:])
	_, err := conn.Write(proto.Build())
	if err != nil {
		return err
	}

	b := make([]byte, confirmLen)
	_, err = conn.Read(b)
	if err != nil {
		return err
	}
	r, err := ParseConfirmResult(b)
	if err != nil {
		return err
	}
	if !r.IsOk() {
		return errors.New("user/password do not match")
	}
	log.Println("OK Confirm")
	return nil
}
