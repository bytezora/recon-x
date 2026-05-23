package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bytezora/recon-x/internal/finding"
	"github.com/bytezora/recon-x/internal/vulns"
)

func TestWriteJSON_IncludesFindings(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "out.json")

	findings := []finding.Finding{{
		Type:       "xss",
		Severity:   finding.High,
		Confidence: finding.Likely,
		Title:      "Reflected XSS",
		RiskScore:  72,
		Priority:   "p1",
	}}

	err := WriteJSON(
		path,
		"example.com",
		nil, nil, nil, nil,
		vulns.EnrichReport{}, vulns.FilterReport{},
		nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil,
		nil, nil, nil,
		findings,
	)
	if err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read json: %v", err)
	}

	var got Report
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal json: %v", err)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got.Findings))
	}
	if got.Findings[0].Priority != "p1" || got.Findings[0].RiskScore != 72 {
		t.Fatalf("unexpected finding payload: %+v", got.Findings[0])
	}
}
