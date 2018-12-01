package groto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"log"
)

type Status byte

const (
	// Ascii
	Init Status = 0x05
	OK   Status = 0x06
	NG   Status = 0x07
)

const (
	initLen    = 1 + 3 + 10 + 20
	confirmLen = 3 + 10 + 10 + 32
	resultLen  = 3 + 10 + 1
)

var version = []byte{0, 0, 1}

type ProtoInit struct {
	status  Status
	version []byte
	id      []byte
	pwhash  []byte
}

func NewProtoInit(s Status) (ProtoInit, error) {
	if s != OK {
		return ProtoInit{
			status:  s,
			version: version,
		}, nil
	}

	id := make([]byte, 10)
	_, err := rand.Read(id)
	if err != nil {
		return ProtoInit{}, err
	}

	pwhash := make([]byte, 20)
	_, err = rand.Read(pwhash)
	if err != nil {
		return ProtoInit{}, err
	}

	return ProtoInit{
		status:  OK,
		version: version,
		id:      id,
		pwhash:  pwhash,
	}, nil
}

func (i *ProtoInit) Build() []byte {
	b := make([]byte, 0, initLen)

	b = append(b, byte(i.status))
	b = append(b, i.version...)
	b = append(b, i.id...)
	b = append(b, i.pwhash...)

	return b
}

func (i *ProtoInit) IsOk() bool {
	return i.status == OK
}

func (i *ProtoInit) Id() []byte {
	return i.id
}

func (i *ProtoInit) PwHash() []byte {
	return i.pwhash
}

func InitApproval(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	return b[0] == byte(Init)
}

func ParseInit(b []byte) (ProtoInit, error) {
	return ProtoInit{
		status:  Status(b[0]),
		version: b[1:4],
		id:      b[4:14],
		pwhash:  b[14:initLen],
	}, nil
}

type ProtoConfirm struct {
	version []byte
	id      []byte
	user    []byte
	hPw     []byte
}

func NewProtoConfirm(id []byte, user []byte, hPw []byte) ProtoConfirm {
	return ProtoConfirm{
		version: version,
		id:      id,
		user:    user,
		hPw:     hPw,
	}
}

func (p *ProtoConfirm) Build() []byte {
	b := make([]byte, 0, confirmLen)

	user := make([]byte, 10)
	copy(user, p.user)
	hPw := make([]byte, 32)
	copy(hPw, p.hPw)

	b = append(b, p.version...)
	b = append(b, p.id...)
	b = append(b, user...)
	b = append(b, hPw...)
	return b
}

func (p *ProtoConfirm) Id() []byte {
	return p.id
}

func (p *ProtoConfirm) Confirm(id, user, hpw []byte) bool {
	if !bytes.Equal(p.id, id) {
		log.Printf("ID: %X, %X", p.id, id)
		return false
	}
	if !bytes.Equal(p.user, user) {
		log.Printf("USER: %X, %X", p.user, user)
		return false
	}
	if !bytes.Equal(p.hPw, hpw) {
		log.Printf("PW: %X, %X", p.hPw, hpw)
		return false
	}
	return true
}

func ParseConfirm(b []byte) (ProtoConfirm, error) {
	p := ProtoConfirm{
		version: b[0:3],
		id:      b[3:13],
		user:    b[13:23],
		hPw:     b[23:confirmLen],
	}
	return p, nil
}

func HashPw(key, pw []byte) [32]byte {
	b := append(key, pw...)
	return sha256.Sum256(b)
}

type ProtoConfirmResult struct {
	version []byte
	id      []byte
	status  Status
}

func NewProtoConfirmResult(id []byte, status Status) ProtoConfirmResult {
	return ProtoConfirmResult{
		version: version,
		id:      id,
		status:  status,
	}
}

func (p *ProtoConfirmResult) Build() []byte {
	b := make([]byte, 0, resultLen)

	b = append(b, p.version...)
	b = append(b, p.id...)
	b = append(b, byte(p.status))

	return b
}

func (p *ProtoConfirmResult) IsOk() bool {
	return p.status == OK
}

func ParseConfirmResult(b []byte) (ProtoConfirmResult, error) {
	return ProtoConfirmResult{
		version: b[0:3],
		id:      b[3:13],
		status:  Status(b[13]),
	}, nil

}
