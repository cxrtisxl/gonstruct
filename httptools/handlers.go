package httptools

import (
	"log/slog"
	"net/http"
)

type Handler interface {
	ServeHTTP(http.ResponseWriter, *http.Request) error
}

type HandlerFunc func(http.ResponseWriter, *http.Request) error

func (f HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return f(w, r)
}

type ErrorHandler func(next Handler) http.Handler

// DefaultErrorHandler middleware is an adapter that supprots HandleFunc
// that return errors. Setting showErr to `true` will cause it
// to return underlying error text if `msg` is empty.
func DefaultErrorHandler(next Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := next.ServeHTTP(w, r)
		if err != nil {
			if statusErr, ok := err.(*StatusError); ok {
				w.WriteHeader(statusErr.Code)
				w.Write([]byte(statusErr.Msg))
				slog.Error(statusErr.Err.Error())
				return
			}
			w.WriteHeader(500)
			slog.Error(err.Error())
		}
	})
}
