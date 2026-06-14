package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bytezora/recon-x/internal/finding"
)

func TestApplySuppressesBaselineAndAllowlist(t *testing.T) {
	items := finding.EnrichAndSort([]finding.Finding{
		{Type: "xss", Severity: finding.High, Title: "Reflected XSS", AffectedURL: "https://example.com/?q=1"},
		{Type: "cors", Severity: finding.Medium, Title: "CORS", AffectedURL: "https://api.example.com"},
		{Type: "sqli", Severity: finding.High, Title: "SQLi", AffectedURL: "https://app.example.com/?id=1"},
	})
	base := map[string]bool{items[0].Fingerprint: true}
	rules := Rules{
		Fingerprints: map[string]bool{},
		Types:        map[string]bool{"cors": true},
		CVEs:         map[string]bool{},
	}

	got, summary := Apply(items, base, rules)
	if len(got) != 1 {
		t.Fatalf("expected 1 remaining finding, got %d", len(got))
	}
	if got[0].Type != "sqli" {
		t.Fatalf("expected SQLi finding to remain, got %s", got[0].Type)
	}
	if summary.BaselineSuppressed != 1 || summary.AllowSuppressed != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
}

func TestLoadFingerprintsComputesMissingFingerprint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	raw, err := json.Marshal(Report{Findings: []finding.Finding{{
		Type:        "xss",
		Severity:    finding.High,
		Title:       "Reflected XSS",
		AffectedURL: "https://example.com/?q=1",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadFingerprints(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one fingerprint, got %d", len(got))
	}
}
