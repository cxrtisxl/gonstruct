package httptools

import "net/http"

type HandlerFunc func(http.ResponseWriter, *http.Request) error

// The ErrorHandler middleware is an adapter that supprots HandleFunc
// that return errors. Setting showErr to `true` will cause it
// to return underlying error text if `msg` is empty.
func ErrorHandler(next HandlerFunc, showErr bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := next(w, r)
		if err != nil {
			if statusErr, ok := err.(*StatusError); ok {
				w.WriteHeader(statusErr.Code)
				if showErr && statusErr.Msg != "" {
					w.Write([]byte(statusErr.Msg))
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
