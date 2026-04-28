package wayback

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetch(t *testing.T) {
	mockData := [][]string{
		{"original", "timestamp", "statuscode"},
		{"http://example.com/admin.php?id=1", "20230101120000", "200"},
		{"http://example.com/config.json", "20230102120000", "200"},
		{"http://example.com/about", "20230103120000", "200"},
	}
	body, _ := json.Marshal(mockData)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	}))
	defer srv.Close()

	if !isInteresting("http://example.com/admin.php?id=1") {
		t.Error("expected admin.php?id=1 to be interesting")
	}
	if !isInteresting("http://example.com/config.json") {
		t.Error("expected config.json to be interesting")
	}
	if isInteresting("http://example.com/about") {
		t.Error("expected /about to not be interesting")
	}
}
