package sanitize

import (
	"strings"
	"testing"

	"github.com/bytezora/recon-x/internal/defaultcreds"
	"github.com/bytezora/recon-x/internal/engine"
	"github.com/bytezora/recon-x/internal/finding"
	"github.com/bytezora/recon-x/internal/jsscan"
)

func TestSecretFullyRedactsWithStableMetadata(t *testing.T) {
	got := Secret("super-secret-token", 100)
	if strings.Contains(got, "super-secret-token") {
		t.Fatalf("secret leaked in redacted output: %q", got)
	}
	if !strings.Contains(got, "len=18") || !strings.Contains(got, "sha256_12=") {
		t.Fatalf("expected metadata in redacted output, got %q", got)
	}
}

func TestResultsRedactsSensitiveOutputs(t *testing.T) {
	res := &engine.Results{
		JS: []jsscan.Finding{{
			Kind:  "secret",
			Label: "Token",
			Value: "token-1234567890",
		}},
		DefaultCreds: []defaultcreds.Result{{
			Username: "admin",
			Password: "admin123",
			Found:    true,
		}},
		Findings: []finding.Finding{{
			Type:     "default-creds",
			Title:    "Default Credentials Accepted: admin:admin123",
			Evidence: "HTTP 200 accepted admin:admin123",
		}},
	}

	Results(res, false, 100)

	if strings.Contains(res.JS[0].Value, "token-1234567890") {
		t.Fatalf("JS secret leaked: %q", res.JS[0].Value)
	}
	if strings.Contains(res.DefaultCreds[0].Password, "admin123") {
		t.Fatalf("default credential leaked: %q", res.DefaultCreds[0].Password)
	}
	if strings.Contains(res.Findings[0].Evidence, "admin123") {
		t.Fatalf("finding evidence leaked: %q", res.Findings[0].Evidence)
	}
}

func TestResultsHonorsShowSecrets(t *testing.T) {
	res := &engine.Results{
		JS: []jsscan.Finding{{Kind: "secret", Value: "token-1234567890"}},
	}
	Results(res, true, 100)
	if res.JS[0].Value != "token-1234567890" {
		t.Fatalf("expected raw secret when showSecrets is true, got %q", res.JS[0].Value)
	}
}
