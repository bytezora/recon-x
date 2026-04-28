package lfi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDetect_LFI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if strings.Contains(file, "passwd") {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:")
		} else {
			fmt.Fprint(w, "not found")
		}
	}))
	defer srv.Close()

	results := Detect([]string{srv.URL + "?file=page.html"}, 5, nil)
	if len(results) == 0 {
		t.Error("expected LFI detection, got none")
	}
}
