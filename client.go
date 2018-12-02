package groto

import (
	"errors"
	"log"
	"net"
)

type Client struct {
	user      string
	password  string
	id        []byte
	pwHashKey []byte
}

func NewClient(user, password string) *Client {
	return &Client{
		user:     user,
		password: password,
	}
}

func (c *Client) Do(conn net.Conn) error {
	if err := c.stepHandshake(conn); err != nil {
		return err
	}
	if err := c.stepAuthN(conn); err != nil {
		return err
	}
	return nil
}

func (c *Client) stepHandshake(conn net.Conn) error {
	_, err := conn.Write([]byte{byte(Init)})
	if err != nil {
		return err
	}

	b := make([]byte, initLen)
	_, err = conn.Read(b)
	if err != nil {
		return err
	}
	i, err := UnmarshalHandshake(b)
	if err != nil {
		return err
	}
	if i.status != OK {
		return errors.New("failed init")
	}
	log.Println("OK Handshake")
	c.id = i.id
	c.pwHashKey = i.pwHashKey

	return nil
}

func (c *Client) stepAuthN(conn net.Conn) error {
	hPw := HashPw(c.pwHashKey, []byte(c.password))
	proto := NewProtoConfirm(c.id, []byte(c.user), hPw[:])
	_, err := conn.Write(proto.Marshal())
	if err != nil {
		return err
	}

	b := make([]byte, confirmLen)
	_, err = conn.Read(b)
	if err != nil {
		return err
	}
	r, err := UnmarshalAuthNResult(b)
	if err != nil {
		return err
	}
	if !r.IsOk() {
		return errors.New("user/password do not match")
	}
	log.Println("OK Confirm")
	return nil
}
