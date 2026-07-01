package jose

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

type ECJWK struct {
	jwk
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (e ECJWK) isJWK() {}

type ecdsaKey struct {
	kid     string
	private *ecdsa.PrivateKey
	public  *ecdsa.PublicKey
}

func newECDSA(key []byte) (Key, error) {
	var k ecdsaKey
	var err error
	// Private key
	block, _ := pem.Decode(key)
	if block == nil {
		return k, errors.New("failed to parse PEM")
	}
	k.private, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return k, err
	}
	// Public key
	k.public = &k.private.PublicKey
	// Generating kid
	bytes, err := x509.MarshalPKIXPublicKey(k.public)
	if err != nil {
		return ecdsaKey{}, errors.New("failed to marshal public key")
	}
	hash := sha256.Sum256(bytes)
	k.kid = hex.EncodeToString(hash[:16])
	return k, nil
}

func (k ecdsaKey) Sign(token *jwt.Token) (string, error) {
	tokenString, err := token.SignedString(k.private)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (k ecdsaKey) JWK() JWK {
	xStr := base64.RawURLEncoding.EncodeToString(k.public.X.Bytes())
	yStr := base64.RawURLEncoding.EncodeToString(k.public.Y.Bytes())
	return ECJWK{
		jwk: jwk{
			Kty: "EC",
			Use: "sig",
			Alg: k.SigningMethod().Alg(),
			Kid: k.kid,
		},
		Crv: "P-256",
		X:   xStr,
		Y:   yStr,
	}
}

func (k ecdsaKey) Kid() string {
	return k.kid
}

func (k ecdsaKey) Public() any {
	return k.public
}

func (k ecdsaKey) SigningMethod() jwt.SigningMethod {
	return jwt.SigningMethodES256
}
