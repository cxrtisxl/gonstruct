package auth

import (
	"errors"
	"net/http"
	"time"

	"github.com/cxrtisxl/gonstruct/auth/authenticator"
	"github.com/cxrtisxl/gonstruct/auth/jose"
	"github.com/cxrtisxl/gonstruct/auth/strategy"
	tools "github.com/cxrtisxl/gonstruct/httptools"
	"github.com/markbates/goth"
)

type Service interface {
	Middleware(next tools.Handler) tools.Handler
	Mount(mux *http.ServeMux, prefix string)
}

type OAuthJWT struct {
	s strategy.Scheme
	a authenticator.Provider
}

func (oaj *OAuthJWT) Middleware(next tools.Handler) tools.Handler {
	return oaj.s.Middleware(next)
}

func (oaj *OAuthJWT) Mount(mux *http.ServeMux, prefix string, errHandler tools.ErrorHandler) {
	oaj.s.Mount(mux, prefix, errHandler)
	oaj.a.Mount(mux, prefix, errHandler)
}

func NewDefault(
	mux *http.ServeMux,
	loginCallback func(user *authenticator.User) (userId string, err *tools.StatusError),
	gothProviders []goth.ProviderConfig,
	web bool,
) (*OAuthJWT, error) {
	refreshInBody := !web
	s, err := strategy.NewEphemeralJWT(strategy.EphemeralJWTOpts{
		KeyType:         jose.KeyTypeECDSA,
		RefreshTokenTTL: 30 * 24 * time.Hour,
		AccessTokenTTL:  15 * time.Minute,
		RefreshInBody:   refreshInBody,
		ErrorHandler:    tools.DefaultErrorHandler,
	})
	if err != nil {
		return nil, err
	}

	a := authenticator.NewOAuthAuthenticator(
		func(user *authenticator.User, w http.ResponseWriter, r *http.Request) error {
			id, err := loginCallback(user)
			if err != nil {
				return err
			}
			if id == "" {
				return &tools.StatusError{
					Code: 500,
					Err:  errors.New("user id was not returned by LoginCallback"),
				}
			}
			return s.IssuePair(id, w, r)
		},
		nil,
		gothProviders,
	)

	return &OAuthJWT{s: s, a: a}, nil
}
