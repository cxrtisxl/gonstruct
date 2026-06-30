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
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/google"
)

func TestGothConfigurableProviders(t *testing.T) {
	loginCallback := func(user *authenticator.User) (userId string, err *tools.StatusError) {
		return rand.Text(), nil
	}

	service, err := auth.NewDefault(
		"http://localhost:8080",
		loginCallback,
		[]goth.ProviderConfig{
			&google.Config{
				ClientKey: os.Getenv("GOOGLE_KEY"),
				Secret:    os.Getenv("GOOGLE_SECRET"),
			},
		},
		false,
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
