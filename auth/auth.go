package auth

import (
	"context"
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
	Mount(mux *http.ServeMux, prefix string, errHandler tools.ErrorHandler) error
}

type OAuthJWT struct {
	a *authenticator.OAuth
	s *strategy.JWT
}

func (oaj *OAuthJWT) Middleware(next tools.Handler) tools.Handler {
	return oaj.s.Middleware(next)
}

func (oaj *OAuthJWT) Mount(
	mux *http.ServeMux,
	prefix string,
	errHandler tools.ErrorHandler,
) error {
	err := oaj.s.Mount(mux, prefix, errHandler)
	if err != nil {
		return err
	}
	err = oaj.a.Mount(mux, prefix, errHandler)
	if err != nil {
		return err
	}
	return nil
}

func (oaj *OAuthJWT) UserID(ctx context.Context) (userID string, ok bool) {
	ctxData, ok := oaj.s.FromContext(ctx).(strategy.CtxData)
	if !ok || ctxData.Type != strategy.TypeJWT {
		return "", false
	}
	claims, ok := ctxData.Data.(jose.AccessClaims)
	if !ok || claims.Subject == "" {
		return "", false
	}
	return claims.Subject, true
}

func NewWebOAuthJWT(
	baseDomain string,
	redirectURL string,
	cookieSameSite http.SameSite,
	loginCallback func(user *authenticator.User) (userID string, err *tools.StatusError),
	gothProviders []goth.ProviderConfig,
) (*OAuthJWT, error) {
	s, err := strategy.NewEphemeralJWT(strategy.EphemeralJWTOpts{
		KeyType:         jose.KeyTypeECDSA,
		RefreshTokenTTL: 30 * 24 * time.Hour,
		AccessTokenTTL:  15 * time.Minute,
		ErrorHandler:    tools.DefaultErrorHandler,
	})
	if err != nil {
		return nil, err
	}

	a := authenticator.NewOAuthAuthenticator(
		baseDomain,
		// Login
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
			return s.IssuePair(id, true, &cookieSameSite, redirectURL, false, false, w, r)
		},
		// Logout
		func(w http.ResponseWriter, r *http.Request) error {
			s.DropCookie(cookieSameSite, w, r)
			return nil
		},
		gothProviders,
	)

	return &OAuthJWT{s: s, a: a}, nil
}
