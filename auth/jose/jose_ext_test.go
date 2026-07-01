package jose_test

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/cxrtisxl/gonstruct/auth/jose"
)

func TestKeychainGeneration(t *testing.T) {
	keychain, err := jose.GenerateKeychain(jose.KeyTypeECDSA)
	if err != nil {
		t.Fatal(err)
	}
	claims := jose.NewAccessClaims("test-uuid", time.Hour)
	token, err := keychain.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	fromToken, err := keychain.VerifyAccess(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != fromToken.Subject {
		t.Fatalf("Subject doesn't match:\n{%s}\n{%s}", claims, fromToken)
	}
	if !claims.ExpiresAt.Time.Equal(fromToken.ExpiresAt.Time) {
		t.Fatalf("ExpiresAt doesn't match:\n{%s}\n{%s}", claims.ExpiresAt, fromToken.ExpiresAt)
	}
}

func TestNewKeychain(t *testing.T) {
	keyB64 := "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSU5TcG0zR29tSWdyUzhzWWxSeU1TR2czZnJhQVBNUWdhci9Nd1lCZmdjRGdvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFMmk5ckNMNzVwSkhHaEFoSlczalR3b00yQUVPNTNYdzh4Ylk5cklaVHVIbmpvZm5GUFZsSQpSam91VTFkYWRTRVpjelY4d1A1ZU01eWZnbUZsSDFwWDVRPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="
	keyb, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		t.Fatal(err)
	}

	key, err := jose.NewKey(jose.KeyTypeECDSA, keyb)
	keychain := jose.NewKeychain(key)

	accessJwt, err := keychain.Sign(jose.NewAccessClaims("1", time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, err = keychain.VerifyAccess(accessJwt)
	if err != nil {
		t.Fatal(err)
	}
}
