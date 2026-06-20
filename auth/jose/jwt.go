package jose

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
)

type AccessClaims struct {
	jwt.RegisteredClaims
	Type string `json:"typ"`
	Role string `json:"role,omitempty"`
}

type RefreshClaims struct {
	jwt.RegisteredClaims
	Type string `json:"typ"`
}

func NewAccessClaims(sub, role string, ttl time.Duration) AccessClaims {
	now := time.Now()
	return AccessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   sub,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Type: TokenTypeAccess,
		Role: role,
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
