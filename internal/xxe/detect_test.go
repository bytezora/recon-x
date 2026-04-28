package xxe

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetect_XXE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
		} else {
			fmt.Fprint(w, "ok")
		}
	}))
	defer srv.Close()

	results := Detect([]string{srv.URL}, 5, nil)
	if len(results) == 0 {
		t.Error("expected XXE detection, got none")
	}
}

func TestDetect_NoXXE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<result>ok</result>")
	}))
	defer srv.Close()

	results := Detect([]string{srv.URL}, 5, nil)
	if len(results) != 0 {
		t.Errorf("expected no XXE detection, got %d", len(results))
	}
}
