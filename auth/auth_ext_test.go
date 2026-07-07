package auth_test

import (
	"context"
	"crypto/rand"
	"net/http"
	"os"
	"testing"

	"github.com/cxrtisxl/gonstruct/auth"
	"github.com/cxrtisxl/gonstruct/auth/authenticator"
	tools "github.com/cxrtisxl/gonstruct/httptools"
	"github.com/joho/godotenv"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/google"
)

func TestGothConfigurableProviders(t *testing.T) {
	err := godotenv.Load()
	if err != nil {
		panic(err)
	}

	loginCallback := func(user *authenticator.User) (userId string, err *tools.StatusError) {
		return rand.Text(), nil
	}

	service, err := auth.NewWebOAuthJWT(
		"https://pac-descending-insider-namespace.trycloudflare.com",
		"https://pac-descending-insider-namespace.trycloudflare.com/dashboard",
		loginCallback,
		[]goth.ProviderConfig{
			&google.Config{
				ClientKey: os.Getenv("GOOGLE_KEY"),
				Secret:    os.Getenv("GOOGLE_SECRET"),
			},
		},
	)
	if err != nil {
		t.Error(err)
	}

	verifyAuth := service.Middleware
	errHandler := tools.DefaultErrorHandler

	done := make(chan int, 1)
	mux := http.NewServeMux()
	srv := &http.Server{Addr: ":8080", Handler: mux}
	service.Mount(mux, "/auth", errHandler)

	completeHandler := tools.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) error {
			w.Write([]byte("test passed"))
			done <- 1
			return nil
		},
	)
	mux.Handle("GET /complete", errHandler(verifyAuth(completeHandler)))

	dashboardHandler := tools.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) error {
			w.Write([]byte(`
				OAuth completed. Refresh token is set to Cookie.
				To complete the test:
				1. GET /auth/refresh (error expected) to get the refresh token from browser Cookies
				2. POST /auth/refresh with refresh_token cookie to get Access Token
				3. GET /complete with Authorization: Bearer [Access Token]
			`))
			return nil
		},
	)
	mux.Handle("GET /dashboard", errHandler(dashboardHandler))

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Errorf("server: %v", err)
		}
	}()
	t.Log("Follow http://localhost:8080/auth/google")
	t.Log("GET http://localhost:8080/complete to complete the test")
	defer srv.Shutdown(context.Background())
	<-done
}
