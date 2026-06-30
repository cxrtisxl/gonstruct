package cors

import (
	"fmt"
	"net/http"
	"strings"
)

type Config struct {
	varyOrigin     bool
	allowedOrigins map[string]bool
	methods        []string
	headers        []string
}

func New(origins []string, methods []string, headers []string) (c *Config) {
	c = &Config{}
	c.allowedOrigins = make(map[string]bool)

	if len(origins) > 1 {
		c.varyOrigin = true
	}

	for _, origin := range origins {
		if origin == "*" {
			c.varyOrigin = true
		}
		c.allowedOrigins[origin] = true
	}

	optionsFound := false
	for _, method := range methods {
		if method == http.MethodOptions {
			optionsFound = true
			break
		}
	}
	if !optionsFound {
		methods = append(methods, http.MethodOptions)
	}

	c.methods = methods
	c.headers = headers

	return c
}

func (c *Config) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if c.allowedOrigins["*"] || c.allowedOrigins[origin] {
			fmt.Println("ORIGIN", c.allowedOrigins[origin], c.allowedOrigins["*"])
			methodsString := strings.Join(c.methods, ", ")
			headersString := strings.Join(c.headers, ", ")

			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", methodsString)
			w.Header().Set("Access-Control-Allow-Headers", headersString)
			if c.varyOrigin {
				w.Header().Set("Vary", "Origin")
			}
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}
