package jose

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

type Key interface {
	Public() any
	Kid() string
	SigningMethod() jwt.SigningMethod
	Sign(token *jwt.Token) (string, error)
	JWK() JWK
}

type KeyType string

const (
	KeyTypeECDSA KeyType = "ecdsa"
)

func NewKey(keyType KeyType, key []byte) (Key, error) {
	switch keyType {
	case KeyTypeECDSA:
		return newECDSA(key)
	}
	return nil, errors.New("key type is not supported")
}
