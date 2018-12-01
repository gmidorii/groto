package groto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
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
	if len(b) != initLen {
		return ProtoInit{}, fmt.Errorf("unexpected len got: %v, want: %v", len(b), initLen)
	}

	return ProtoInit{
		status:  Status(b[0]),
		version: b[1:4],
		id:      b[4:15],
		pwhash:  b[15:34],
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

	b = append(b, p.id...)
	b = append(b, p.user...)
	b = append(b, p.hPw...)

	return b
}

func ParseConfirm(b []byte) (ProtoConfirm, error) {
	if len(b) != confirmLen {
		return ProtoConfirm{}, fmt.Errorf("unexpected len got: %v, want: %v", len(b), confirmLen)
	}

	return ProtoConfirm{
		version: b[0:3],
		id:      b[3:13],
		user:    b[13:23],
		hPw:     b[23:confirmLen],
	}, nil

}

func HashPw(key, pw []byte) []byte {
	h := sha256.New()
	h.Write(key)
	return h.Sum(pw)
}
