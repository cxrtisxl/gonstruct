package httptools

import "net/http"

type Handler interface {
	ServeHTTP(http.ResponseWriter, *http.Request) error
}

type HandlerFunc func(http.ResponseWriter, *http.Request) error

func (f HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return f(w, r)
}

type ErrorHandler func(next Handler) http.Handler

// The ErrorHandler middleware is an adapter that supprots HandleFunc
// that return errors. Setting showErr to `true` will cause it
// to return underlying error text if `msg` is empty.
func DefaultErrorHandler(next Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := next.ServeHTTP(w, r)
		if err != nil {
			if statusErr, ok := err.(*StatusError); ok {
				w.WriteHeader(statusErr.Code)
				if statusErr.Msg != "" {
					w.Write([]byte(http.StatusText(statusErr.Code)))
					return
				}
				w.Write([]byte(statusErr.Error()))
				return
			}
			w.WriteHeader(500)
			w.Write([]byte(err.Error()))
		}
	})
}
