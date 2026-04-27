package sqli

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBodyDiffers(t *testing.T) {
	h := sha256.Sum256([]byte("abc123"))
	baseline := hex.EncodeToString(h[:])
	if bodyDiffers(baseline, "abc123") {
		t.Error("expected identical body to not differ")
	}
	if !bodyDiffers(baseline, "different content") {
		t.Error("expected different body to differ")
	}
}

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

func TestDetect_ConfidenceHigh(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
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
		if r.Detected && r.Confidence != "high" {
			t.Errorf("expected high confidence, got %s", r.Confidence)
		}
	}
}
