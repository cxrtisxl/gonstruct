package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

type Keychain struct {
	methods    []string
	keys       map[string]Key
	primaryKey Key
	jwks       JWKS
}

func GenerateKeychain(keyType KeyType) (*Keychain, error) {
	switch keyType {
	case KeyTypeECDSA:
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(ecdsaKey)
		if err != nil {
			return nil, err
		}
		keyb := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: der,
		})
		key, err := NewKey(KeyTypeECDSA, keyb)
		if err != nil {
			return nil, err
		}
		return NewKeychain(key), nil
	default:
		return nil, errors.New("key type is not supported")
	}
}

func NewKeychain(primaryKey Key, keys ...Key) *Keychain {
	keychain := Keychain{
		keys:       make(map[string]Key),
		primaryKey: primaryKey,
	}
	pkKid := primaryKey.Kid()
	keychain.keys[pkKid] = primaryKey
	keychain.methods = append(keychain.methods, primaryKey.SigningMethod().Alg())
	keychain.jwks.Keys = append(keychain.jwks.Keys, primaryKey.JWK())

	methodSeen := map[string]bool{pkKid: true}
	for _, key := range keys {
		keychain.keys[key.Kid()] = key
		alg := key.SigningMethod().Alg()
		if _, ok := methodSeen[alg]; !ok {
			keychain.methods = append(keychain.methods, alg)
		}
		keychain.jwks.Keys = append(keychain.jwks.Keys, key.JWK())
	}
	return &keychain
}

func (k Keychain) Key(kid string) (key Key, ok bool) {
	key, ok = k.keys[kid]
	return key, ok
}

func (k Keychain) Sign(claims jwt.Claims) (string, error) {
	return k.signWith(k.primaryKey, claims)
}

func (k Keychain) SignWith(kid string, claims jwt.Claims) (string, error) {
	key, ok := k.keys[kid]
	if !ok {
		return "", errors.New("keychain: wrong kid provided")
	}
	return k.signWith(key, claims)
}

func (k Keychain) signWith(key Key, claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(key.SigningMethod(), claims)
	token.Header["kid"] = key.Kid()
	return key.Sign(token)
}

func (k Keychain) VerifyInto(token string, claims jwt.Claims) error {
	_, err := jwt.ParseWithClaims(token, claims,
		func(t *jwt.Token) (any, error) {
			kidVal, ok := t.Header["kid"]
			if !ok {
				return nil, errors.New("keychain verify: no kid in token header")
			}
			kid, ok := kidVal.(string)
			if !ok {
				return nil, errors.New("keychain verify: kid is in wrong format")
			}
			key, ok := k.keys[kid]
			if !ok {
				return nil, errors.New("keychain verify: no key with matching kid")
			}
			return key.Public(), nil
		},
		jwt.WithValidMethods(k.methods),
	)
	return err
}

func (k Keychain) VerifyAccess(token string) (AccessClaims, error) {
	var claims AccessClaims
	err := k.VerifyInto(token, &claims)
	if err != nil {
		return AccessClaims{}, err
	}
	if claims.Type != TokenTypeAccess {
		return AccessClaims{}, ErrWrongTokenType
	}
	return claims, nil
}

func (k Keychain) VerifyRefresh(token string) (RefreshClaims, error) {
	var claims RefreshClaims
	err := k.VerifyInto(token, &claims)
	if err != nil {
		return RefreshClaims{}, err
	}
	if claims.Type != TokenTypeAccess {
		return RefreshClaims{}, ErrWrongTokenType
	}
	return claims, nil
}

func (k Keychain) JWKS() JWKS {
	return k.jwks
}
