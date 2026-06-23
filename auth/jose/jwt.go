package jose

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
)

type AccessClaims struct {
	jwt.RegisteredClaims
	Type TokenType `json:"typ"`
}

type RefreshClaims struct {
	jwt.RegisteredClaims
	Type TokenType `json:"typ"`
}

func NewAccessClaims(sub string, ttl time.Duration) AccessClaims {
	now := time.Now()
	return AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Type: TokenTypeAccess,
	}
}

func NewRefreshClaims(sub string, ttl time.Duration) RefreshClaims {
	now := time.Now()
	return RefreshClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Type: TokenTypeRefresh,
	}
}

var ErrWrongTokenType = errors.New("wrong typ")
