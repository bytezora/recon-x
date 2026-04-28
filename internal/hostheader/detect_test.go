package hostheader

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetect_HostHeaderInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xfh := r.Header.Get("X-Forwarded-Host")
		if xfh != "" {
			fmt.Fprintf(w, "<a href='https://%s/path'>link</a>", xfh)
		} else {
			fmt.Fprint(w, "<html>normal page</html>")
		}
	}))
	defer srv.Close()

	results := Detect([]string{srv.URL}, 5, nil)
	if len(results) == 0 {
		t.Error("expected host header injection detection, got none")
	}
}

func TestDetect_NoInjection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>static page, no reflection</html>")
	}))
	defer srv.Close()

	results := Detect([]string{srv.URL}, 5, nil)
	if len(results) != 0 {
		t.Errorf("expected no detection for non-reflecting server, got %d", len(results))
	}
}
