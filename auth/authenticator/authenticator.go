package authenticator

import (
	"net/http"

	tools "github.com/cxrtisxl/gonstruct/httptools"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
)

type Type string

const TypeOAuth Type = "oauth"

type Provider interface {
	Mount(mux *http.ServeMux, prefix string, errHandler tools.ErrorHandler)
	Type() Type
}

type LoginHandler func(user *User, w http.ResponseWriter, r *http.Request) error

type OAuthAuthenticator struct {
	loginHandler  LoginHandler
	logoutHandler tools.HandlerFunc
}

func NewOAuthAuthenticator(
	loginHandler LoginHandler,
	logoutHandler tools.HandlerFunc,
	gothProviders []goth.Provider,
) *OAuthAuthenticator {
	goth.UseProviders(gothProviders...)
	return &OAuthAuthenticator{
		loginHandler:  loginHandler,
		logoutHandler: logoutHandler,
	}
}

func (oa *OAuthAuthenticator) Type() Type {
	return TypeOAuth
}

func (oa *OAuthAuthenticator) Mount(mux *http.ServeMux, prefix string, errHandler tools.ErrorHandler) {
	mux.Handle("GET "+prefix+"/{provider}", errHandler(tools.HandlerFunc(oa.AuthHandler)))
	mux.Handle("GET "+prefix+"/{provider}/callback", errHandler(tools.HandlerFunc(oa.CallbackHandler)))
	mux.Handle("POST "+prefix+"/logout", errHandler(tools.HandlerFunc(tools.HandlerFunc(oa.LogoutHandler))))
}

func (oa *OAuthAuthenticator) AuthHandler(w http.ResponseWriter, r *http.Request) error {
	gothUser, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		gothic.BeginAuthHandler(w, r)
		return nil
	}
	if oa.loginHandler != nil {
		user := UserFromGoth(gothUser)
		return oa.loginHandler(&user, w, r)
	}
	return nil
}

func (oa *OAuthAuthenticator) CallbackHandler(w http.ResponseWriter, r *http.Request) error {
	gothUser, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		return &tools.StatusError{
			Code: http.StatusInternalServerError,
			Err:  err,
		}
	}
	if oa.loginHandler != nil {
		user := UserFromGoth(gothUser)
		return oa.loginHandler(&user, w, r)
	}
	return nil
}

func (oa *OAuthAuthenticator) LogoutHandler(w http.ResponseWriter, r *http.Request) error {
	err := gothic.Logout(w, r)
	if err != nil {
		return &tools.StatusError{
			Code: http.StatusInternalServerError,
			Err:  err,
		}
	}
	if oa.logoutHandler != nil {
		return oa.logoutHandler(w, r)
	}
	return nil
}
