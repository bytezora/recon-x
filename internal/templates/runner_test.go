package templates

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMatchWords(t *testing.T) {
	if !matchWords("hello world", []string{"world"}) {
		t.Error("expected match")
	}
	if matchWords("hello world", []string{"missing"}) {
		t.Error("expected no match")
	}
	if matchWords("hello", []string{}) {
		t.Error("expected no match on empty words")
	}
}

func TestMatchStatus(t *testing.T) {
	if !matchStatus(200, []int{200, 302}) {
		t.Error("expected status 200 to match")
	}
	if matchStatus(404, []int{200, 302}) {
		t.Error("expected status 404 to not match")
	}
	if matchStatus(200, []int{}) {
		t.Error("expected no match on empty statuses")
	}
}

func TestProbeTemplate_WordMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("secret-token-found"))
	}))
	defer srv.Close()

	tpl := Template{
		ID:       "test-001",
		Name:     "Test Word Match",
		Severity: "high",
		Request:  RequestDef{Method: "GET", Path: "/"},
		Matchers: []MatcherDef{{Type: "word", Words: []string{"secret-token-found"}}},
	}

	m := probeTemplate(tpl, srv.URL)
	if m == nil {
		t.Fatal("expected a match")
	}
	if m.TemplateID != "test-001" {
		t.Errorf("expected template ID test-001, got %s", m.TemplateID)
	}
}

func TestProbeTemplate_StatusMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer srv.Close()

	tpl := Template{
		ID:       "test-002",
		Name:     "Test Status Match",
		Severity: "medium",
		Request:  RequestDef{Method: "GET", Path: "/admin"},
		Matchers: []MatcherDef{{Type: "status", Status: []int{403}}},
	}

	m := probeTemplate(tpl, srv.URL)
	if m == nil {
		t.Fatal("expected a match for status 403")
	}
}

func TestProbeTemplate_NoMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("nothing interesting"))
	}))
	defer srv.Close()

	tpl := Template{
		ID:       "test-003",
		Name:     "Test No Match",
		Severity: "low",
		Request:  RequestDef{Method: "GET", Path: "/"},
		Matchers: []MatcherDef{{Type: "word", Words: []string{"secret"}}},
	}

	m := probeTemplate(tpl, srv.URL)
	if m != nil {
		t.Error("expected no match")
	}
}
