package sqli

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetect_NoParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	results := Detect([]string{srv.URL + "/"}, 1, nil)
	for _, r := range results {
		if r.Detected {
			t.Error("expected no detection on clean response")
		}
	}
}

func TestDetect_SQLiFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("id") != "" && r.URL.Query().Get("id") != "1" {
			w.Write([]byte("You have an error in your SQL syntax"))
			return
		}
		w.Write([]byte("normal response"))
	}))
	defer srv.Close()

	var found []Result
	results := Detect([]string{srv.URL + "/?id=1"}, 1, func(r Result) {
		found = append(found, r)
	})

	detected := false
	for _, r := range results {
		if r.Detected {
			detected = true
		}
	}
	if !detected {
		t.Error("expected SQLi to be detected")
	}
	_ = found
}

func TestDetect_ConfidenceHighOrConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id != "" && id != "1" {
			w.Write([]byte("You have an error in your SQL syntax - injected"))
			return
		}
		w.Write([]byte("normal response baseline"))
	}))
	defer srv.Close()

	results := Detect([]string{srv.URL + "/?id=1"}, 1, nil)
	for _, r := range results {
		if r.Detected && r.Confidence != "high" && r.Confidence != "confirmed" {
			t.Errorf("expected high or confirmed confidence, got %s", r.Confidence)
		}
	}
}
