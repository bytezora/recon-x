package xss

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetect_Reflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("q")
		fmt.Fprintf(w, "<html><body>%s</body></html>", val)
	}))
	defer srv.Close()

	results := Detect([]string{srv.URL + "?q=hello"}, 5, nil)
	if len(results) == 0 {
		t.Error("expected XSS detection, got none")
	}
	for _, r := range results {
		if !r.Reflected {
			t.Error("expected Reflected=true")
		}
	}
}

func TestDetect_Safe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("q")
		safe := ""
		for _, c := range val {
			switch c {
			case '<':
				safe += "&lt;"
			case '>':
				safe += "&gt;"
			default:
				safe += string(c)
			}
		}
		fmt.Fprintf(w, "<html><body>%s</body></html>", safe)
	}))
	defer srv.Close()

	results := Detect([]string{srv.URL + "?q=hello"}, 5, nil)
	if len(results) != 0 {
		t.Errorf("expected no XSS detection for safe output, got %d", len(results))
	}
}
