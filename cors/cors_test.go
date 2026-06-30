package cors

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestCORSMiddleware(t *testing.T) {
	type TestExpected struct {
		pass    bool
		origin  string
		methods string
		headers string
	}
	type TestConfig struct {
		origin   string
		origins  []string
		methods  []string
		headers  []string
		expected TestExpected
	}
	var tests []TestConfig = []TestConfig{
		{
			"https://app.example.com",
			[]string{"*"},
			[]string{"GET", "OPTIONS", "POST"},
			[]string{"Authorization"},
			TestExpected{
				pass:    true,
				origin:  "https://app.example.com",
				methods: "GET, OPTIONS, POST",
				headers: "Authorization",
			},
		},
		{
			"https://app.example.com",
			[]string{"*"},
			[]string{"GET", "POST"},
			[]string{"Content-Type", "Authorization"},
			TestExpected{
				pass:    true,
				origin:  "https://app.example.com",
				methods: "GET, POST, OPTIONS",
				headers: "Content-Type, Authorization",
			},
		},
		{
			"https://app.not-allowed-origin.com",
			[]string{"https://app.example.com"},
			[]string{"OPTIONS"},
			[]string{"Content-Type"},
			TestExpected{
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
		srv := &http.Server{Addr: ":8080", Handler: mux}
		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				t.Errorf("server: %v", err)
			}
		}()

		req, err := http.NewRequest(http.MethodGet, "http://localhost:8080/test", nil)
		req.Header["Origin"] = []string{test.origin}
		if err != nil {
			t.Fatal("request error: ", err)
		}
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal("client error: ", err)
		}

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

		resp.Body.Close()
		srv.Shutdown(context.Background())
	}
}
