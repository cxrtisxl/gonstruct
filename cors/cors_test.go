package cors

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSMiddleware(t *testing.T) {
	type Expected struct {
		pass    bool
		origin  string
		methods string
		headers string
	}
	type Config struct {
		origin   string
		origins  []string
		methods  []string
		headers  []string
		expected Expected
	}
	tests := []Config{
		{
			origin:  "https://app.example.com",
			origins: []string{"*"},
			methods: []string{"GET", "OPTIONS", "POST"},
			headers: []string{"Authorization"},
			expected: Expected{
				pass:    true,
				origin:  "https://app.example.com",
				methods: "GET, OPTIONS, POST",
				headers: "Authorization",
			},
		},
		{
			origin:  "https://app.example.com",
			origins: []string{"*"},
			methods: []string{"GET", "POST"},
			headers: []string{"Content-Type", "Authorization"},
			expected: Expected{
				pass:    true,
				origin:  "https://app.example.com",
				methods: "GET, POST, OPTIONS",
				headers: "Content-Type, Authorization",
			},
		},
		{
			origin:  "https://app.not-allowed-origin.com",
			origins: []string{"https://app.example.com"},
			methods: []string{"OPTIONS"},
			headers: []string{"Content-Type"},
			expected: Expected{
				pass: false,
			},
		},
	}

	for _, test := range tests {
		cors := New(test.origins, test.methods, test.headers)
		mux := http.NewServeMux()
		mux.Handle("GET /test",
			cors.Middleware(
				http.HandlerFunc(
					func(w http.ResponseWriter, r *http.Request) {
						w.Write([]byte("success"))
					},
				),
			),
		)
		srv := httptest.NewServer(mux)
		defer srv.Close()

		req, err := http.NewRequest(http.MethodGet, srv.URL+"/test", nil)
		req.Header["Origin"] = []string{test.origin}
		if err != nil {
			t.Fatal("request error: ", err)
		}
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal("client error: ", err)
		}
		resp.Body.Close()

		if test.expected.pass {
			got := resp.Header["Access-Control-Allow-Credentials"][0]
			expected := "true"
			if got != expected {
				t.Fatal("Access-Control-Allow-Credentials got: " + got + "\nExpected: " + expected)
			}
			got = resp.Header["Access-Control-Allow-Headers"][0]
			expected = test.expected.headers
			if got != expected {
				t.Fatal("Access-Control-Allow-Headers got: " + got + "\nExpected: " + expected)
			}
			got = resp.Header["Access-Control-Allow-Methods"][0]
			expected = test.expected.methods
			if got != expected {
				t.Fatal("Access-Control-Allow-Methods got: " + got + "\nExpected: " + expected)
			}
			got = resp.Header["Access-Control-Allow-Origin"][0]
			expected = test.expected.origin
			if got != expected {
				t.Fatal("Access-Control-Allow-Origin got: " + got + "\nExpected: " + expected)
			}
		} else {
			if len(resp.Header["Access-Control-Allow-Credentials"]) != 0 ||
				len(resp.Header["Access-Control-Allow-Headers"]) != 0 ||
				len(resp.Header["Access-Control-Allow-Methods"]) != 0 ||
				len(resp.Header["Access-Control-Allow-Origin"]) != 0 {

				b, _ := json.Marshal(resp.Header)
				t.Fatal("Test expected to fail but it passed with: " + string(b))
			}
		}
	}
}
