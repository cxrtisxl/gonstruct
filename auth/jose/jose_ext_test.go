package jose_test

import (
	"encoding/base64"
	"log"
	"testing"
	"time"

	"github.com/cxrtisxl/gonstruct/auth/jose"
)

func TestNewKeychain(t *testing.T) {
	keyB64 := "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSU5TcG0zR29tSWdyUzhzWWxSeU1TR2czZnJhQVBNUWdhci9Nd1lCZmdjRGdvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFMmk5ckNMNzVwSkhHaEFoSlczalR3b00yQUVPNTNYdzh4Ylk5cklaVHVIbmpvZm5GUFZsSQpSam91VTFkYWRTRVpjelY4d1A1ZU01eWZnbUZsSDFwWDVRPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="
	keyb, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		log.Fatal(err)
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
