package jose

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type JWK interface {
	isJWK()
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}
