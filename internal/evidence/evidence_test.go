package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bytezora/recon-x/internal/vulns"
)

func TestEvaluateFilesCalculatesPrecisionRecall(t *testing.T) {
	dir := t.TempDir()
	scanPath := filepath.Join(dir, "scan.json")
	truthPath := filepath.Join(dir, "truth.json")

	writeJSON(t, scanPath, scanReport{
		Target:      "lab.local",
		GeneratedAt: "2026-05-23T00:00:00Z",
		Vulns: []vulns.Match{
			{Host: "lab.local", Port: 80, Product: "apache", Version: "2.4.49", CVE: "CVE-2021-41773", Confidence: "high"},
			{Host: "lab.local", Port: 80, Product: "apache", Version: "2.4.49", CVE: "CVE-IGNORED", Confidence: "medium"},
			{Host: "lab.local", Port: 22, Product: "openssh", Version: "9.6", CVE: "CVE-2023-48795", Confidence: "high"},
		},
	})
	writeJSON(t, truthPath, Truth{
		Name:       "unit lab",
		IgnoreCVEs: []string{"CVE-IGNORED"},
		Cases: []Case{
			{
				Name:         "apache vulnerable",
				Host:         "lab.local",
				Port:         80,
				Product:      "apache",
				Version:      "2.4.49",
				ExpectedCVEs: []string{"CVE-2021-41773", "CVE-2021-42013"},
			},
			{
				Name:         "openssh terrapin",
				Host:         "lab.local",
				Port:         22,
				Product:      "openssh",
				Version:      "9.6",
				ExpectedCVEs: []string{"CVE-2023-48795"},
			},
		},
	})

	report, err := EvaluateFiles(scanPath, truthPath, "test", 0.90)
	if err != nil {
		t.Fatalf("EvaluateFiles() error = %v", err)
	}
	if report.Passed {
		t.Fatalf("expected report to fail 90%% recall threshold")
	}
	if report.Totals.TruePositive != 2 || report.Totals.FalsePositive != 0 || report.Totals.FalseNegative != 1 {
		t.Fatalf("unexpected totals: %+v", report.Totals)
	}
	if report.Totals.Precision != 1 {
		t.Fatalf("precision = %v, want 1", report.Totals.Precision)
	}
	if got, want := report.Totals.Recall, float64(2)/float64(3); got != want {
		t.Fatalf("recall = %v, want %v", got, want)
	}
	if len(report.Ignored) != 1 {
		t.Fatalf("ignored findings = %d, want 1", len(report.Ignored))
	}
}

func TestEvaluateFilesCountsOutsideScopeFalsePositive(t *testing.T) {
	dir := t.TempDir()
	scanPath := filepath.Join(dir, "scan.json")
	truthPath := filepath.Join(dir, "truth.json")

	writeJSON(t, scanPath, scanReport{
		Vulns: []vulns.Match{
			{Host: "lab.local", Port: 80, CVE: "CVE-OK"},
			{Host: "extra.local", Port: 443, CVE: "CVE-OUTSIDE"},
		},
	})
	writeJSON(t, truthPath, Truth{
		Cases: []Case{
			{Host: "lab.local", Port: 80, ExpectedCVEs: []string{"CVE-OK"}},
		},
	})

	report, err := EvaluateFiles(scanPath, truthPath, "test", 0.90)
	if err != nil {
		t.Fatalf("EvaluateFiles() error = %v", err)
	}
	if report.Totals.TruePositive != 1 || report.Totals.FalsePositive != 1 || report.Totals.FalseNegative != 0 {
		t.Fatalf("unexpected totals: %+v", report.Totals)
	}
	if len(report.OutsideScopeFP) != 1 {
		t.Fatalf("outside-scope false positives = %d, want 1", len(report.OutsideScopeFP))
	}
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
}
