package strategy

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
	Mount(mux *http.ServeMux, prefix string, errHandler tools.ErrorHandler) error
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
}

type EphemeralJWTOpts struct {
	KeyType         jose.KeyType
	RefreshTokenTTL time.Duration
	AccessTokenTTL  time.Duration
	ErrorHandler    tools.ErrorHandler
}

type JWTOpts struct {
	PrimaryKey      jose.Key
	Keys            []jose.Key
	RefreshTokenTTL time.Duration
	AccessTokenTTL  time.Duration
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
	}, nil
}

func NewJWT(opts JWTOpts) *JWT {
	return &JWT{
		keychain:        jose.NewKeychain(opts.PrimaryKey, opts.Keys...),
		refreshTokenTTL: opts.RefreshTokenTTL,
		accessTokenTTL:  opts.AccessTokenTTL,
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
		r = r.WithContext(context.WithValue(r.Context(), ctxDataKey, CtxData{Type: TypeJWT, Data: claims}))
		return next.ServeHTTP(w, r)
	})
}

func (j *JWT) FromContext(ctx context.Context) any {
	return ctx.Value(ctxDataKey)
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

// IssuePair issues an access/refresh JWT pair for sub and decides how to
// deliver them to the client: via cookie, JSON body, or redirect.
//
// Parameters:
//
//   - setCookie — if true, the refresh token is set as an httpOnly cookie
//     named "refresh_token" with Path="/auth/refresh". Use for browser
//     clients (web login, OAuth callback). If false, the refresh token is
//     not put in a cookie — use jsonIncludeRefresh to return it instead.
//
//   - cookieSameSite - if setCookie is true, configures http.SameSite
//     for the refresh token Cookie. If nil fallbacks to http.SameSiteDefaultMode
//
//   - redirect — if a non-empty string, after the cookie is set the
//     function calls http.Redirect(w, r, redirect, http.StatusFound) and
//     returns without writing a JSON body. Use only for top-level GET
//     navigation by the browser (e.g. an OAuth callback), never for
//     fetch/XHR requests — the redirect will be swallowed by the client
//     instead of applied to the page. If redirect is non-empty,
//     jsonIncludeRefresh and jsonIncludeAccess are ignored: no body is
//     written.
//
//   - jsonIncludeRefresh — if true (and redirect == ""), refresh_token is
//     added to the JSON response body. Use for non-browser clients (mobile
//     apps, server-to-server API clients) that have no cookie jar.
//
//   - jsonIncludeAccess — if true (and redirect == ""), access_token is
//     added to the JSON response body.
//
// If redirect == "" and both jsonInclude* flags are false, an empty JSON
// object "{}" is returned with a 200 status — a valid case for web login
// via fetch, where access is fetched separately via /auth/refresh rather
// than through IssuePair directly.
//
// Typical combinations:
//
//	Client                        setCookie  redirect      jsonIncludeRefresh  jsonIncludeAccess
//	OAuth callback (browser)      true       "/dashboard"  —                   —
//	Web login via fetch (SPA)     true       ""            false               false
//	Mobile app / API client       false      ""            true                true
//
// setCookie=false combined with a non-empty redirect is syntactically
// allowed but has no practical use: a non-browser client won't act on a
// 302 anyway.
func (j *JWT) IssuePair(
	sub string,
	setCookie bool,
	cookieSameSite *http.SameSite,
	redirect string,
	jsonIncludeRefresh bool,
	jsonIncludeAccess bool,
	w http.ResponseWriter,
	r *http.Request,
) error {
	accessToken, err := j.NewToken(jose.TokenTypeAccess, sub)
	if err != nil {
		return &tools.StatusError{Code: 500, Err: err}
	}

	refreshToken, err := j.NewToken(jose.TokenTypeRefresh, sub)
	if err != nil {
		return &tools.StatusError{Code: 500, Err: err}
	}

	if setCookie {
		sameSite := http.SameSiteDefaultMode
		if cookieSameSite != nil {
			sameSite = *cookieSameSite
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    refreshToken,
			Path:     "/auth/refresh",
			HttpOnly: true,
			Secure:   true,
			SameSite: sameSite,
			MaxAge:   int(j.refreshTokenTTL.Seconds()),
		})
	}

	if redirect != "" {
		http.Redirect(w, r, redirect, http.StatusFound)
		return nil
	}

	body := map[string]string{}
	if jsonIncludeRefresh {
		body["refresh_token"] = refreshToken
	}
	if jsonIncludeAccess {
		body["access_token"] = accessToken
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(body)
}

func (j *JWT) Refresh(w http.ResponseWriter, r *http.Request) error {
	c, err := r.Cookie("refresh_token")
	if err != nil {
		return &tools.StatusError{Code: 401, Err: err}
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

func (j *JWT) Mount(mux *http.ServeMux, prefix string, errHandler tools.ErrorHandler) error {
	jwksHandler, err := j.JWKSHandler()
	if err != nil {
		return err
	}
	mux.Handle("GET /.well-known/jwks.json", jwksHandler)
	mux.Handle("POST "+prefix+"/refresh", errHandler(tools.HandlerFunc(j.Refresh)))
	return nil
}

func (j *JWT) JWKSHandler() (http.Handler, error) {
	jwksCached, err := json.Marshal(j.keychain.JWKS())
	if err != nil {
		return nil, errors.New("failed to marshal keychain JWKS")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksCached)
	}), nil
}
