package ssrf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetect_SSRF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		val := r.URL.Query().Get("url")
		if val != "" {
			fmt.Fprintf(w, "fetching: %s ami-id instance-id", val)
		} else {
			fmt.Fprint(w, "ok")
		}
	}))
	defer srv.Close()

	results := Detect([]string{srv.URL + "?url=http://example.com"}, 5, nil)
	if len(results) == 0 {
		t.Error("expected SSRF detection, got none")
	}
}

func TestDetect_NoSSRFParam(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	results := Detect([]string{srv.URL + "?id=1"}, 5, nil)
	if len(results) != 0 {
		t.Errorf("expected no SSRF detection for non-SSRF param, got %d", len(results))
	}
}
