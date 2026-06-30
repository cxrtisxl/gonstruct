package strategy

// TODO OId config

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/cxrtisxl/gonstruct/auth/jose"
	tools "github.com/cxrtisxl/gonstruct/httptools"
)

type Scheme interface {
	Middleware(next tools.Handler) tools.Handler
	Mount(mux *http.ServeMux, prefix string, errHandler tools.ErrorHandler)
	Type() Type
}

type ctxKey int

const ctxDataKey ctxKey = iota

type Type string

const TypeJWT Type = "jwt"

type CtxData struct {
	Type Type
	Data any
}

type JWT struct {
	keychain        *jose.Keychain
	refreshTokenTTL time.Duration
	accessTokenTTL  time.Duration
	refreshInBody   bool
}

type EphemeralJWTOpts struct {
	KeyType         jose.KeyType
	RefreshTokenTTL time.Duration
	AccessTokenTTL  time.Duration
	RefreshInBody   bool
	ErrorHandler    tools.ErrorHandler
}

type JWTOpts struct {
	PrimaryKey      jose.Key
	Keys            []jose.Key
	RefreshTokenTTL time.Duration
	AccessTokenTTL  time.Duration
	RefreshInBody   bool
	ErrorHandler    tools.ErrorHandler
}

func NewEphemeralJWT(opts EphemeralJWTOpts) (*JWT, error) {
	keychain, err := jose.GenerateKeychain(opts.KeyType)
	if err != nil {
		return nil, err
	}
	return &JWT{
		keychain:        keychain,
		refreshTokenTTL: opts.RefreshTokenTTL,
		accessTokenTTL:  opts.AccessTokenTTL,
		refreshInBody:   opts.RefreshInBody,
	}, nil
}

func NewJWT(opts JWTOpts) *JWT {
	return &JWT{
		keychain:        jose.NewKeychain(opts.PrimaryKey, opts.Keys...),
		refreshTokenTTL: opts.RefreshTokenTTL,
		accessTokenTTL:  opts.AccessTokenTTL,
		refreshInBody:   opts.RefreshInBody,
	}
}

func (j *JWT) Type() Type {
	return TypeJWT
}

func (j *JWT) Middleware(next tools.Handler) tools.Handler {
	return tools.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		h := r.Header.Get("Authorization")
		scheme, token, found := strings.Cut(h, " ")
		if !found || !strings.EqualFold(scheme, "Bearer") {
			return &tools.StatusError{Code: 401, Err: errors.New("invalid Authorization scheme")}
		}
		if token == "" {
			return &tools.StatusError{Code: 401, Err: errors.New("empty bearer token")}
		}

		claims, err := j.VerifyAccess(token)
		if err != nil {
			return &tools.StatusError{
				Code: 401,
				Err:  err,
			}
		}
		r.WithContext(context.WithValue(r.Context(), ctxDataKey, CtxData{Type: TypeJWT, Data: claims}))
		return next.ServeHTTP(w, r)
	})
}

func (j *JWT) NewToken(typ jose.TokenType, sub string) (token string, err error) {
	switch typ {
	case jose.TokenTypeAccess:
		return j.keychain.Sign(jose.NewAccessClaims(sub, j.accessTokenTTL))
	case jose.TokenTypeRefresh:
		return j.keychain.Sign(jose.NewRefreshClaims(sub, j.refreshTokenTTL))
	}
	return "", errors.New("token type is not supported")
}

func (j *JWT) IssuePair(sub string, w http.ResponseWriter, r *http.Request) error {
	accessToken, err := j.NewToken(jose.TokenTypeAccess, sub)
	if err != nil {
		return &tools.StatusError{Code: 500, Err: err}
	}

	refreshToken, err := j.NewToken(jose.TokenTypeRefresh, sub)
	if err != nil {
		return &tools.StatusError{Code: 500, Err: err}
	}

	body := map[string]string{}
	if j.refreshInBody {
		body["access_token"] = accessToken
		body["refresh_token"] = refreshToken
	} else {
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    refreshToken,
			Path:     "/auth/refresh",
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(j.refreshTokenTTL.Seconds()),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(body)
}

func (j *JWT) Refresh(w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie("refresh_token")
	if err != nil {
		return &tools.StatusError{Code: 401, Err: errors.New("no refresh token")}
	}
	claims, err := j.keychain.VerifyRefresh(c.Value)
	if err != nil {
		return &tools.StatusError{Code: 401, Err: err}
	}
	accessToken, err := j.NewToken(jose.TokenTypeAccess, claims.Subject)
	if err != nil {
		return &tools.StatusError{Code: 500, Err: err}
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(map[string]string{"access_token": accessToken})
}

func (j *JWT) VerifyAccess(token string) (jose.AccessClaims, error) {
	claims, err := j.keychain.VerifyAccess(token)
	if err != nil {
		return jose.AccessClaims{}, err
	}
	return claims, nil
}

func (j *JWT) Mount(mux *http.ServeMux, prefix string, errHandler tools.ErrorHandler) {
	mux.Handle("GET /.well-known/jwks.json", j.JwksHandler())
	mux.Handle("POST "+prefix+"/refresh", errHandler(tools.HandlerFunc(j.Refresh)))
}

func (j *JWT) JwksHandler() http.Handler {
	jwksCached, err := json.Marshal(j.keychain.JWKS())
	if err != nil {
		panic(err)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksCached)
	})
}
