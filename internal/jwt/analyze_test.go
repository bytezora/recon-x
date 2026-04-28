package jwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bytezora/recon-x/internal/httpcheck"
)

func makeJWT(header, payload map[string]interface{}) string {
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	h := base64.RawURLEncoding.EncodeToString(hb)
	p := base64.RawURLEncoding.EncodeToString(pb)
	sig := "fakesig"
	return h + "." + p + "." + sig
}

func TestAnalyze_AlgNone(t *testing.T) {
	tok := makeJWT(
		map[string]interface{}{"alg": "none", "typ": "JWT"},
		map[string]interface{}{"sub": "user1", "exp": 9999999999},
	)
	body := `{"token": "` + tok + `"}`
	results := Analyze([]httpcheck.Result{{URL: "http://example.com", Body: body}}, 5, nil)
	found := false
	for _, r := range results {
		if strings.Contains(r.Issue, "alg:none") {
			found = true
		}
	}
	if !found {
		t.Error("expected alg:none detection")
	}
}

func TestAnalyze_MissingExp(t *testing.T) {
	tok := makeJWT(
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"sub": "user1"},
	)
	body := `{"token": "` + tok + `"}`
	results := Analyze([]httpcheck.Result{{URL: "http://example.com", Body: body}}, 5, nil)
	found := false
	for _, r := range results {
		if strings.Contains(r.Issue, "exp") {
			found = true
		}
	}
	if !found {
		t.Error("expected missing-exp detection")
	}
}
