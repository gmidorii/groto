package groto

import (
	"errors"
	"fmt"
	"log"
	"net"
)

const readLen = 2 * 1024
const user = "user"
const password = "password"

type Server struct {
	hashKey []byte
}

func NewServer() *Server {
	return &Server{}
}

func (s *Server) Do(conn net.Conn) error {
	if err := s.stepInit(conn); err != nil {
		return err
	}
	if err := s.stepConfirm(conn); err != nil {
		return err
	}
	return nil
}

func (s *Server) stepInit(conn net.Conn) error {
	b := make([]byte, readLen)
	_, err := conn.Read(b)
	if err != nil {
		return fmt.Errorf("failed read connection: %v", err)
	}

	if !InitApproval(b) {
		i, err := NewPacketHandshake(NG)
		if err != nil {
			return fmt.Errorf("failed create init proto: %v", err)
		}
		_, err = conn.Write(i.Marshal())
		if err != nil {
			return fmt.Errorf("failed write: %v", err)
		}

		return errors.New("connection first byte must be 0x05")
	}
	log.Println("OK Connection")

	i, err := NewPacketHandshake(OK)
	if err != nil {
		return fmt.Errorf("failed create init proto: %v", err)
	}
	_, err = conn.Write(i.Marshal())
	if err != nil {
		return err
	}
	s.hashKey = i.pwHashKey
	return nil
}

func (s *Server) stepConfirm(conn net.Conn) error {
	b := make([]byte, readLen)
	_, err := conn.Read(b)
	if err != nil {
		return fmt.Errorf("failed read connection: %v", err)
	}

	c, err := UnmarshalAuthN(b)
	if err != nil {
		return fmt.Errorf("failed parse confirm packet: %v", err)
	}
	u := make([]byte, 10)
	copy(u, []byte(user))
	p := HashPw(s.hashKey, []byte(password))

	if !c.Confirm(c.id, u, p[:]) {
		r := NewPacketAuthNResult(c.Id(), NG)
		_, err = conn.Write(r.Marshal())
		if err != nil {
			return err
		}
		return nil
	}
	r := NewPacketAuthNResult(c.Id(), OK)
	_, err = conn.Write(r.Marshal())
	if err != nil {
		return err
	}

	return nil
}
