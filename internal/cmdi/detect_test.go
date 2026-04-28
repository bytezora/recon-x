package cmdi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDetect_CMDi_Output(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cmd := r.URL.Query().Get("cmd")
		if strings.Contains(cmd, "id") || strings.Contains(cmd, "whoami") {
			fmt.Fprint(w, "uid=33(www-data) gid=33(www-data) groups=33(www-data)")
		} else {
			fmt.Fprint(w, "ok")
		}
	}))
	defer srv.Close()

	results := Detect([]string{srv.URL + "?cmd=ls"}, 5, nil)
	if len(results) == 0 {
		t.Error("expected CMDi detection, got none")
	}
}

func TestDetect_NoCMDi(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok normal response")
	}))
	defer srv.Close()

	results := Detect([]string{srv.URL + "?id=1"}, 5, nil)
	if len(results) != 0 {
		t.Errorf("expected no CMDi detection, got %d", len(results))
	}
}
